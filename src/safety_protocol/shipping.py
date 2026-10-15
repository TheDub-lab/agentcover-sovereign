# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Michael / TheDub-lab
"""
Log shipping — ship each guard decision to an external receiver.

This is the sender half of the log-shipping protocol (v1). It lives in the
MIT SDK: any guard can stream its decisions to a receiver the operator does
not control, so the hash chain becomes third-party evidence.

Design:

  * Every decision becomes one canonical JSON event. The event's ``hash`` is
    the SHA-256 of the event with the ``hash`` field removed, serialized with
    sorted keys and no whitespace (UTF-8). ``prev_hash`` chains to the
    previous event; seq 1 chains to 64 zeros.
  * Privacy: raw params are NEVER shipped by default. Only ``params_digest``
    (SHA-256 of canonical params) and ``param_keys`` go out. ``log_params``
    can be "none" (default), "redacted" (secret-looking values masked), or
    "full".
  * Shipping is asynchronous and durable. Events are appended to a local
    outbox (JSONL) FIRST, then sent in batches. Restarts resume from the
    outbox; failures retry with backoff. The action never waits on the
    receiver.

The receiver (verification + signed receipts) is the BSL platform layer.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import threading
import time
import uuid
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .core import ActionOutcome

ZERO_HASH = "0" * 64

# Keys whose values look like secrets — masked when log_params == "redacted".
_SECRET_KEY_RE = re.compile(r"(key|token|secret|password|passwd|auth|credential)", re.I)

_OUTCOME_TO_DECISION = {
    "allowed": "allowed",
    "blocked_scope": "denied",
    "blocked_budget": "denied",
    "pending_approval": "needs_approval",
    "blocked_killswitch": "killswitch",
}

VALID_DECISIONS = (
    "allowed", "denied", "needs_approval", "approved", "rejected", "killswitch",
)


# ---------------------------------------------------------------------------
# Canonicalisation / hashing
# ---------------------------------------------------------------------------

def canonical_json(obj) -> bytes:
    """Canonical form for hashing: sorted keys, no whitespace, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, default=str).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def params_digest(params: dict | None) -> str:
    """SHA-256 of canonical params. Params are never raw-shipped by default."""
    return sha256_hex(canonical_json(params or {}))


def config_hash(cfg: dict) -> str:
    """SHA-256 of the active config — proves which limits were in force."""
    return sha256_hex(canonical_json(cfg))


def hash_event(event: dict) -> str:
    """SHA-256 of the event with the ``hash`` field removed."""
    body = {k: v for k, v in event.items() if k != "hash"}
    return sha256_hex(canonical_json(body))


def verify_event_hash(event: dict) -> bool:
    """True if the event's stored ``hash`` matches its recomputed hash."""
    return event.get("hash") == hash_event(event)


def _iso_z(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _mask_params(params: dict) -> dict:
    out = {}
    for k, v in params.items():
        out[k] = "***" if _SECRET_KEY_RE.search(k) else v
    return out


# ---------------------------------------------------------------------------
# Durable outbox (JSONL + state file)
# ---------------------------------------------------------------------------

class Outbox:
    """Append-only local outbox.

    Files in ``path``:
      events.jsonl   — one canonical event per line (the chain, in order)
      state.json     — {next_seq, head_hash, acked_seq}
      receipts.jsonl — signed receipts from the receiver

    Events are fsynced on append so a crash cannot lose a decision that was
    already made. ``acked_seq`` is advanced only after the receiver accepts a
    batch (or reports a higher head), so anything unacknowledged is resent.
    """

    def __init__(self, path: str):
        self.path = path
        os.makedirs(path, exist_ok=True)
        self._events_path = os.path.join(path, "events.jsonl")
        self._state_path = os.path.join(path, "state.json")
        self._receipts_path = os.path.join(path, "receipts.jsonl")
        self._state = self._load_state()

    def _load_state(self) -> dict:
        if os.path.exists(self._state_path):
            with open(self._state_path, encoding="utf-8") as f:
                return json.load(f)
        return {"next_seq": 1, "head_hash": None, "acked_seq": 0}

    def _save_state(self) -> None:
        tmp = self._state_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self._state, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self._state_path)

    # -- chain ---------------------------------------------------------
    def next_seq(self) -> int:
        return self._state["next_seq"]

    def head_hash(self) -> str:
        return self._state["head_hash"] or ZERO_HASH

    def append(self, event: dict) -> None:
        line = canonical_json(event).decode("utf-8")
        with open(self._events_path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
            f.flush()
            os.fsync(f.fileno())
        self._state["next_seq"] = event["seq"] + 1
        self._state["head_hash"] = event["hash"]
        self._save_state()

    # -- pending / ack -------------------------------------------------
    def acked_seq(self) -> int:
        return self._state["acked_seq"]

    def pending(self, limit: int) -> list[dict]:
        acked = self._state["acked_seq"]
        out: list[dict] = []
        if not os.path.exists(self._events_path):
            return out
        with open(self._events_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                ev = json.loads(line)
                if ev["seq"] > acked:
                    out.append(ev)
                    if len(out) >= limit:
                        break
        return out

    def ack(self, seq: int) -> None:
        if seq > self._state["acked_seq"]:
            self._state["acked_seq"] = seq
            self._save_state()

    def reset_to(self, seq: int) -> None:
        """Re-send from ``seq`` (used on a 409 gap/mismatch)."""
        self._state["acked_seq"] = max(0, seq - 1)
        self._save_state()

    # -- receipts ------------------------------------------------------
    def store_receipt(self, receipt: dict) -> None:
        with open(self._receipts_path, "a", encoding="utf-8") as f:
            f.write(canonical_json(receipt).decode("utf-8") + "\n")
            f.flush()
            os.fsync(f.fileno())

    def latest_receipt(self) -> dict | None:
        if not os.path.exists(self._receipts_path):
            return None
        last = None
        with open(self._receipts_path, encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    last = line
        return json.loads(last) if last else None


# ---------------------------------------------------------------------------
# HTTP transport
# ---------------------------------------------------------------------------

def http_post_json(url: str, api_key: str, payload: dict,
                   timeout: float = 10.0) -> tuple[int, dict | None]:
    """POST canonical JSON. Returns (status, parsed_body_or_None).

    A 4xx/5xx that carries a JSON body is returned as (status, body) rather
    than raised, so callers can act on 409 gap messages. Transport errors
    raise (caller retries).
    """
    data = canonical_json(payload)
    req = Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    if api_key:
        req.add_header("Authorization", f"Bearer {api_key}")
    try:
        with urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", "replace")
            return resp.status, (json.loads(body) if body else None)
    except HTTPError as e:
        body = e.read().decode("utf-8", "replace")
        try:
            return e.code, (json.loads(body) if body else None)
        except json.JSONDecodeError:
            return e.code, None


# ---------------------------------------------------------------------------
# The shipper
# ---------------------------------------------------------------------------

class LogShipper:
    """Builds decision events, persists them, and ships them to a receiver.

    Use :meth:`emit` as a decision sink (``protocol.add_decision_sink``), or
    call it directly. :meth:`start` runs the background flush/heartbeat loop.
    """

    def __init__(
        self,
        *,
        receiver_url: str,
        api_key: str,
        agent_id: str,
        config_hash: str,
        outbox_dir: str,
        mode: str = "enforce",
        batch_size: int = 50,
        flush_interval_s: float = 5.0,
        heartbeat_interval_s: float = 60.0,
        log_params: str = "none",
        guard_version: str = "",
        transport=None,
        timeout: float = 10.0,
    ):
        if log_params not in ("none", "redacted", "full"):
            raise ValueError("log_params must be none|redacted|full")
        self.receiver_url = receiver_url.rstrip("/")
        self.api_key = api_key
        self.agent_id = agent_id
        self.config_hash = config_hash
        self.mode = mode
        self.batch_size = max(1, min(int(batch_size), 100))
        self.flush_interval_s = float(flush_interval_s)
        self.heartbeat_interval_s = float(heartbeat_interval_s)
        self.log_params = log_params
        self.guard_version = guard_version
        self._transport = transport or http_post_json
        self.timeout = timeout

        self.outbox = Outbox(outbox_dir)
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.last_error: str | None = None

    # -- event building -------------------------------------------------
    def build_event(self, request, result, decision: str | None = None) -> dict:
        override = decision
        policy_outcome = result.execution_log.get("policy_outcome")
        if policy_outcome:
            policy_decision = _OUTCOME_TO_DECISION.get(policy_outcome, "denied")
        else:
            policy_decision = _OUTCOME_TO_DECISION.get(result.outcome.value, "denied")

        if override in ("approved", "rejected"):
            policy_decision = override
            final_decision = override
        elif override == "killswitch" or policy_decision == "killswitch":
            policy_decision = "killswitch"
            final_decision = "killswitch"
        else:
            final_decision = ("allowed" if result.outcome == ActionOutcome.ALLOWED
                              else policy_decision)

        reason = result.execution_log.get("policy_reason") or result.block_reason

        seq = self.outbox.next_seq()
        prev_hash = self.outbox.head_hash()
        event = {
            "v": 1,
            "event_id": str(uuid.uuid4()),
            "agent_id": self.agent_id,
            "seq": seq,
            "ts": _iso_z(request.timestamp),
            "action_type": request.action_type,
            "target": request.target,
            "method": request.method,
            "cost": request.estimated_cost,
            "params_digest": params_digest(request.params),
            "param_keys": sorted(request.params.keys()),
            "policy_decision": policy_decision,
            "decision": final_decision,
            "rule_id": result.execution_log.get("rule_id"),
            "reason": reason,
            "mode": self.mode,
            "config_hash": self.config_hash,
            "prev_hash": prev_hash,
        }
        if self.log_params == "redacted":
            event["params"] = _mask_params(request.params)
        elif self.log_params == "full":
            event["params"] = request.params
        event["hash"] = hash_event(event)
        return event

    def emit(self, request, result, decision: str | None = None) -> dict:
        """Decision sink: build + persist an event. Never blocks on network."""
        with self._lock:
            event = self.build_event(request, result, decision)
            self.outbox.append(event)
            return event

    # -- shipping -------------------------------------------------------
    def flush_once(self) -> dict | None:
        """Send one batch. Returns the receipt on success, else None."""
        batch = self.outbox.pending(self.batch_size)
        if not batch:
            return None
        url = f"{self.receiver_url}/v1/events"
        status, body = self._transport(url, self.api_key, {
            "agent_id": self.agent_id,
            "events": batch,
        }, self.timeout)
        if status == 200 and isinstance(body, dict):
            self.outbox.ack(body.get("head_seq", batch[-1]["seq"]))
            self.outbox.store_receipt(body)
            self.last_error = None
            return body
        if status == 409 and isinstance(body, dict):
            # Gap/mismatch: resend from the receiver's expected seq.
            expected = body.get("expected_seq")
            if isinstance(expected, int):
                self.outbox.reset_to(expected)
            self.last_error = f"receiver reported gap at {expected}"
            return None
        self.last_error = f"receiver returned {status}"
        return None

    def send_heartbeat(self) -> bool:
        url = f"{self.receiver_url}/v1/heartbeat"
        payload = {
            "agent_id": self.agent_id,
            "ts": _iso_z(time.time()),
            "head_seq": self.outbox.next_seq() - 1,
            "head_hash": self.outbox.head_hash(),
            "mode": self.mode,
            "config_hash": self.config_hash,
            "guard_version": self.guard_version,
        }
        status, _ = self._transport(url, self.api_key, payload, self.timeout)
        return status == 200

    # -- background loop ------------------------------------------------
    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, name="log-shipper", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=timeout)
            self._thread = None

    def _run(self) -> None:
        backoff = self.flush_interval_s
        last_hb = 0.0
        while not self._stop.is_set():
            try:
                receipt = self.flush_once()
                if receipt is not None:
                    backoff = self.flush_interval_s
            except (URLError, OSError, TimeoutError) as e:
                self.last_error = str(e)
                backoff = min(backoff * 2, 300.0)
            except Exception as e:  # never let the shipper die
                self.last_error = str(e)
            now = time.time()
            if self.heartbeat_interval_s and now - last_hb >= self.heartbeat_interval_s:
                with contextlib.suppress(Exception):
                    self.send_heartbeat()
                last_hb = now
            self._stop.wait(max(self.flush_interval_s, backoff if self.last_error else 0))

    # -- status ---------------------------------------------------------
    def status(self) -> dict:
        return {
            "receiver_url": self.receiver_url,
            "agent_id": self.agent_id,
            "mode": self.mode,
            "head_seq": self.outbox.next_seq() - 1,
            "head_hash": self.outbox.head_hash(),
            "acked_seq": self.outbox.acked_seq(),
            "pending": max(0, (self.outbox.next_seq() - 1) - self.outbox.acked_seq()),
            "log_params": self.log_params,
            "last_error": self.last_error,
            "running": bool(self._thread and self._thread.is_alive()),
        }


def shipper_from_config(cfg: dict, *, agent_id: str | None = None,
                        transport=None, guard_version: str = "") -> LogShipper | None:
    """Build a LogShipper from a guard config's ``shipping`` block, or None.

    Expected config::

        "shipping": {
          "receiver_url": "https://logs.example.com",
          "api_key": "per-agent key",
          "batch_size": 50,
          "flush_interval_s": 5,
          "heartbeat_interval_s": 60,
          "log_params": "none",
          "outbox_dir": ".safety_outbox"
        },
        "mode": "enforce"
    """
    block = cfg.get("shipping")
    if not block or not block.get("receiver_url"):
        return None
    agent_id = agent_id or cfg.get("agent_id", "guard-agent")
    outbox_dir = block.get("outbox_dir") or os.path.join(
        ".safety_outbox", agent_id)
    return LogShipper(
        receiver_url=block["receiver_url"],
        api_key=block.get("api_key", ""),
        agent_id=agent_id,
        config_hash=config_hash(cfg),
        outbox_dir=outbox_dir,
        mode=cfg.get("mode", "enforce"),
        batch_size=block.get("batch_size", 50),
        flush_interval_s=block.get("flush_interval_s", 5),
        heartbeat_interval_s=block.get("heartbeat_interval_s", 60),
        log_params=block.get("log_params", "none"),
        guard_version=guard_version,
        transport=transport,
    )
