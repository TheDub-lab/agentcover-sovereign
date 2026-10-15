# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 Michael / TheDub-lab
"""
Log receiver — the third-party evidence endpoint.

Endpoints (v1):

  POST /v1/events                 ingest a batch (max 100 events)
  POST /v1/heartbeat              liveness + head for one agent
  GET  /v1/agents/{id}/events     query stored events
  GET  /v1/agents/{id}/verify     re-verify the stored hash chain
  GET  /v1/agents/{id}/report     monthly JSON summary
  POST /v1/admin/clients          create a client
  POST /v1/admin/agents           create an agent (returns its API key once)

Ingest verifies each event's own hash and that prev_hash/seq continue the
stored chain, is idempotent for exact resends, rejects forks (same seq,
different hash) with 409, and returns a signed receipt. The receipt is the
evidence: a receiver-issued, verifiable statement that a given chain head
existed at a given time.

The HTTP surface is stdlib only. ``Receiver.dispatch`` is transport-free so
it can be unit-tested without sockets.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from ...shipping import verify_event_hash
from .signing import ReceiptSigner
from .store import Store

MAX_BATCH = 100


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _hash_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


class Receiver:
    """Transport-free receiver core. Returns (status, body) from each call."""

    def __init__(self, store: Store, admin_key: str | None = None,
                 signer: ReceiptSigner | None = None):
        self.store = store
        self.admin_key = admin_key
        if signer is None:
            key_hex = store.meta_get("receipt_signing_key")
            signer = ReceiptSigner(key_hex)
            if key_hex is None:
                store.meta_set("receipt_signing_key", signer.private_key_hex())
        self.signer = signer

    # -- auth ----------------------------------------------------------
    def _agent_for_key(self, api_key: str) -> dict | None:
        if not api_key:
            return None
        return self.store.get_agent_by_key_hash(_hash_key(api_key))

    def _is_admin(self, api_key: str) -> bool:
        return bool(self.admin_key) and secrets.compare_digest(api_key, self.admin_key)

    def _auth(self, api_key: str, agent_id: str | None = None,
              admin: bool = False) -> tuple[int, dict] | None:
        if admin:
            if not self._is_admin(api_key):
                return 401, {"error": "admin key required"}
            return None
        if self._is_admin(api_key):
            return None
        agent = self._agent_for_key(api_key)
        if agent is None:
            return 401, {"error": "invalid api key"}
        if agent_id is not None and agent["agent_id"] != agent_id:
            return 403, {"error": "agent mismatch"}
        return None

    # -- ingest --------------------------------------------------------
    def ingest(self, api_key: str, body: dict) -> tuple[int, dict]:
        agent_id = body.get("agent_id", "")
        auth = self._auth(api_key, agent_id=agent_id)
        if auth:
            return auth
        events = body.get("events")
        if not isinstance(events, list) or not events:
            return 400, {"error": "no events"}
        if len(events) > MAX_BATCH:
            return 400, {"error": f"batch too large (max {MAX_BATCH})"}

        head_seq, head_hash = self.store.head(agent_id)
        for ev in events:
            if not isinstance(ev, dict):
                return 400, {"error": "malformed event"}
            if ev.get("agent_id") != agent_id:
                return 403, {"error": "event agent mismatch"}
            if not verify_event_hash(ev):
                return 400, {"error": "hash mismatch", "seq": ev.get("seq")}
            seq = ev.get("seq")
            existing = self.store.get_event(agent_id, seq)
            if existing is not None:
                if existing["hash"] == ev.get("hash"):
                    continue  # idempotent resend
                return 409, {
                    "error": "fork", "seq": seq,
                    "expected_seq": head_seq + 1,
                    "expected_prev_hash": head_hash,
                }
            if seq != head_seq + 1 or ev.get("prev_hash") != head_hash:
                return 409, {
                    "error": "gap",
                    "expected_seq": head_seq + 1,
                    "expected_prev_hash": head_hash,
                }
            self.store.append_event(agent_id, ev)
            head_seq, head_hash = seq, ev["hash"]

        fields = {
            "agent_id": agent_id,
            "head_seq": head_seq,
            "head_hash": head_hash,
            "received_at": _now(),
        }
        receipt = {**fields, "sig": self.signer.sign(fields), "sig_alg": self.signer.alg}
        self.store.append_receipt(receipt)
        return 200, receipt

    # -- heartbeat -----------------------------------------------------
    def heartbeat(self, api_key: str, body: dict) -> tuple[int, dict]:
        agent_id = body.get("agent_id", "")
        auth = self._auth(api_key, agent_id=agent_id)
        if auth:
            return auth
        self.store.append_heartbeat(agent_id, body)
        return 200, {"ok": True, "received_at": _now()}

    # -- reads ---------------------------------------------------------
    def list_events(self, api_key: str, agent_id: str, query: dict) -> tuple[int, dict]:
        auth = self._auth(api_key, agent_id=agent_id)
        if auth:
            return auth

        def _int(name):
            v = query.get(name)
            if isinstance(v, list):
                v = v[0]
            return int(v) if v not in (None, "") else None

        def _str(name):
            v = query.get(name)
            if isinstance(v, list):
                v = v[0]
            return v or None

        events = self.store.events(
            agent_id, from_seq=_int("from"), to_seq=_int("to"),
            decision=_str("decision"), limit=_int("limit") or 1000)
        return 200, {"agent_id": agent_id, "count": len(events), "events": events}

    def verify(self, api_key: str, agent_id: str) -> tuple[int, dict]:
        auth = self._auth(api_key, agent_id=agent_id)
        if auth:
            return auth
        return 200, self.store.verify_chain(agent_id)

    def report(self, api_key: str, agent_id: str, query: dict) -> tuple[int, dict]:
        auth = self._auth(api_key, agent_id=agent_id)
        if auth:
            return auth
        month = query.get("month")
        if isinstance(month, list):
            month = month[0]
        events = self.store.events(agent_id, limit=10_000_000)
        if month:
            events = [e for e in events if str(e.get("ts", "")).startswith(month)]
        by_decision: dict[str, int] = {}
        total_cost = 0.0
        for e in events:
            by_decision[e.get("decision")] = by_decision.get(e.get("decision"), 0) + 1
            cost = e.get("cost") or 0
            try:
                total_cost += float(cost)
            except (TypeError, ValueError):
                total_cost += 0.0
        return 200, {
            "agent_id": agent_id,
            "month": month,
            "event_count": len(events),
            "by_decision": by_decision,
            "total_cost": round(total_cost, 6),
            "head_seq": self.store.head(agent_id)[0],
            "latest_receipt": self.store.latest_receipt(agent_id),
            "latest_heartbeat": self.store.latest_heartbeat(agent_id),
        }

    # -- admin ---------------------------------------------------------
    def create_client(self, api_key: str, body: dict) -> tuple[int, dict]:
        auth = self._auth(api_key, admin=True)
        if auth:
            return auth
        client_id = body.get("client_id")
        if not client_id:
            return 400, {"error": "client_id required"}
        return 200, self.store.create_client(client_id, body.get("name", client_id))

    def create_agent(self, api_key: str, body: dict) -> tuple[int, dict]:
        auth = self._auth(api_key, admin=True)
        if auth:
            return auth
        agent_id = body.get("agent_id")
        if not agent_id:
            return 400, {"error": "agent_id required"}
        client_id = body.get("client_id", "")
        api = secrets.token_urlsafe(32)
        self.store.create_agent(agent_id, client_id, _hash_key(api))
        # The raw key is returned exactly once and never stored.
        return 200, {"agent_id": agent_id, "client_id": client_id, "api_key": api}

    # -- routing -------------------------------------------------------
    def dispatch(self, method: str, path: str, query: dict,
                 api_key: str, body: dict) -> tuple[int, dict]:
        if path == "/v1/events" and method == "POST":
            return self.ingest(api_key, body)
        if path == "/v1/heartbeat" and method == "POST":
            return self.heartbeat(api_key, body)
        if path == "/v1/admin/clients" and method == "POST":
            return self.create_client(api_key, body)
        if path == "/v1/admin/agents" and method == "POST":
            return self.create_agent(api_key, body)

        parts = path.strip("/").split("/")
        if len(parts) >= 4 and parts[0] == "v1" and parts[1] == "agents":
            agent_id = parts[2]
            tail = parts[3]
            if tail == "events" and method == "GET":
                return self.list_events(api_key, agent_id, query)
            if tail == "verify" and method == "GET":
                return self.verify(api_key, agent_id)
            if tail == "report" and method == "GET":
                return self.report(api_key, agent_id, query)
        return 404, {"error": "not found"}


# ---------------------------------------------------------------------------
# HTTP adapter
# ---------------------------------------------------------------------------

class _Handler(BaseHTTPRequestHandler):
    receiver: Receiver = None  # set by serve()

    def log_message(self, *a):
        pass

    def _send(self, code: int, payload: dict):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _api_key(self) -> str:
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return auth[7:].strip()
        return ""

    def _body(self) -> dict:
        n = int(self.headers.get("Content-Length", 0) or 0)
        if not n:
            return {}
        try:
            return json.loads(self.rfile.read(n).decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {}

    def _route(self, method: str):
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        body = self._body() if method == "POST" else {}
        code, payload = self.receiver.dispatch(
            method, parsed.path, query, self._api_key(), body)
        self._send(code, payload)

    def do_GET(self):
        self._route("GET")

    def do_POST(self):
        self._route("POST")


def serve(db_path: str, host: str = "127.0.0.1", port: int = 8787,
          admin_key: str | None = None):
    store = Store(db_path)
    receiver = Receiver(store, admin_key=admin_key)
    _Handler.receiver = receiver
    httpd = ThreadingHTTPServer((host, port), _Handler)
    print(f"[receiver] listening on http://{host}:{port}  db={db_path}")
    print(f"[receiver] receipt signing: {receiver.signer.alg}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[receiver] stopped")
    finally:
        store.close()
