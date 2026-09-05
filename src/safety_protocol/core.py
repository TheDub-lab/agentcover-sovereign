"""
Core types and data structures for the safety protocol framework.
"""

from __future__ import annotations
import time
import re
import uuid
import enum
import json
import hashlib
from dataclasses import dataclass, field
from typing import Any
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Core types
# ---------------------------------------------------------------------------

class ActionOutcome(enum.Enum):
    """The outcome of an action request through the safety protocol."""
    ALLOWED = "allowed"
    BLOCKED_SCOPE = "blocked_scope"
    BLOCKED_BUDGET = "blocked_budget"
    PENDING_APPROVAL = "pending_approval"
    BLOCKED_KILLSWITCH = "blocked_killswitch"


class ProtocolState(enum.Enum):
    """The state of the safety protocol."""
    ACTIVE = "active"
    FROZEN = "frozen"       # kill switch engaged, all actions blocked
    REVOKED = "revoked"     # binding revoked, agent can't act at all


@dataclass
class ActionRequest:
    """What the agent wants to do."""
    action_type: str          # e.g. "api_call", "spend", "write_file", "send_message"
    target: str              # what it's acting on
    params: dict = field(default_factory=dict)
    method: str | None = None  # HTTP/transport verb (GET, POST, DELETE, …)
    estimated_cost: float = 0.0
    urgency: str = "normal"  # "low", "normal", "high", "critical"
    request_id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    timestamp: float = field(default_factory=time.time)


@dataclass
class ActionResult:
    """Outcome of an action request."""
    request_id: str
    outcome: ActionOutcome
    block_reason: str | None = None
    requires_approval_for: str | None = None  # if PENDING_APPROVAL
    executed: bool = False
    execution_log: dict = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


@dataclass
class ApprovalRecord:
    """A human approval decision."""
    request_id: str
    approved: bool
    approver: str
    reason: str | None = None
    timestamp: float = field(default_factory=time.time)


class MatchKind(enum.Enum):
    """How a target pattern is compared against an action target."""
    EXACT = "exact"        # target == pattern (after normalization)
    PREFIX = "prefix"      # target starts with pattern (URL/base-path safe)
    GLOB = "glob"          # fnmatch: "https://api.x/v1/*" matches subpaths
    REGEX = "regex"        # re.fullmatch against normalized target
    TOKEN = "token"        # forbidden only: blocks if pattern is a full
                           # path/label token (api/admin, admin.api, role=admin)
                           # but NOT readmymind / administrator
    SUBSTRING = "substring"  # forbidden only: raw containment (legacy, loose)


def normalize_target(target: str) -> str:
    """Normalize a target for comparison.

    Lowercases, collapses repeated slashes, strips a trailing slash.
    This makes HTTPS://API.X/V1/Users and https://api.x/v1/users the
    same target — so casing/encoding tricks can't slip past the allowlist.
    """
    t = target.strip().lower()
    # Collapse repeated slashes, but preserve the "://" of a scheme
    # (e.g. https:// must stay https://, not https:/).
    t = re.sub(r"(?<!:)//+", "/", t)
    t = t.rstrip("/")
    return t


def validate_params(params: dict, schema: dict) -> str | None:
    """Validate `params` against a JSON-schema-style `schema`.

    Subset supported (enough for least-privilege param binding):
      - "required": [keys] that must be present
      - "properties": { key: {type, enum, minimum, maximum, pattern} }
      - "additional_properties": bool (default False — reject unknown keys)

    Returns None if valid, or a human-readable reason string if not.
    This is the param half of least-privilege: a rule that allows a
    target but ignores params is still broad — the agent can pass
    ?confirm=true or a wildcard id and do something the rule didn't mean.
    """
    if schema is None:
        return None

    props = schema.get("properties", {})
    required = schema.get("required", [])
    additional = schema.get("additional_properties", False)

    # Unknown keys
    if not additional:
        for k in params:
            if k not in props:
                return f"param '{k}' is not permitted by this scope rule"

    # Required keys
    for k in required:
        if k not in params:
            return f"required param '{k}' is missing"

    # Per-property checks
    for k, spec in props.items():
        if k not in params:
            continue
        v = params[k]
        t = spec.get("type")
        if t == "string" and not isinstance(v, str):
            return f"param '{k}' must be a string"
        if t == "number" and not isinstance(v, (int, float)):
            return f"param '{k}' must be a number"
        if t == "integer" and not isinstance(v, int):
            return f"param '{k}' must be an integer"
        if t == "boolean" and not isinstance(v, bool):
            return f"param '{k}' must be a boolean"
        if "enum" in spec and v not in spec["enum"]:
            return f"param '{k}'={v!r} not in allowed set {spec['enum']}"
        if "minimum" in spec and isinstance(v, (int, float)) and v < spec["minimum"]:
            return f"param '{k}'={v} below minimum {spec['minimum']}"
        if "maximum" in spec and isinstance(v, (int, float)) and v > spec["maximum"]:
            return f"param '{k}'={v} above maximum {spec['maximum']}"
        if "pattern" in spec and isinstance(v, str) and not re.fullmatch(spec["pattern"], v):
            return f"param '{k}'={v!r} fails pattern {spec['pattern']}"
    return None


def target_matches(pattern: str, target: str, kind: str) -> bool:
    """Return True if `target` matches `pattern` under `kind` matching."""
    kind = MatchKind(kind) if not isinstance(kind, MatchKind) else kind
    tn = normalize_target(target)
    pn = normalize_target(pattern)

    if kind == MatchKind.EXACT:
        return tn == pn
    if kind == MatchKind.PREFIX:
        return tn == pn or tn.startswith(pn + "/")
    if kind == MatchKind.GLOB:
        import fnmatch
        return fnmatch.fnmatch(tn, pn)
    if kind == MatchKind.REGEX:
        return re.fullmatch(pn, tn) is not None
    if kind == MatchKind.TOKEN:
        # Split into segment tokens on common delimiters; block only if the
        # pattern equals a whole token exactly. 'admin' blocks /api/admin and
        # role=admin, but NOT readmymind, administrator, or radmin — token
        # containment within a word is a false positive we explicitly avoid.
        tokens = re.split(r"[/.?#&=+_\-]", tn)
        return pattern.lower() in tokens
    if kind == MatchKind.SUBSTRING:
        return pattern.lower() in tn
    return False


@dataclass
class ScopeRule:
    """A single, PRECISE, least-privilege scope boundary.

    Scope is deny-by-default: an action is allowed only if a rule
    explicitly permits it. Build rules as narrow allowlists, not as
    hopes that you forbade everything dangerous.

    A rule binds FIVE things, every one enforced — leaving any of them
    broad is what makes the other controls decorative:

      - action_type : comes from a closed vocabulary (SafetyProtocol.
                       allowed_action_types). An unregistered verb is
                       blocked before any rule is consulted.
      - allowed_targets + match : where the action may hit. Use EXACT or
                       narrow PREFIX/GLOB/REGEX — a broad prefix like
                       /v1/ lets /v1/admin and /v1/delete slip through.
      - methods : which HTTP/transport verbs are permitted (GET, POST, …).
                  A read rule that also permits DELETE is not least-privilege.
      - param_schema : a JSON-schema-style dict the params MUST satisfy
                       (required keys, types, enum/range constraints).
                       Unvalidated params are how a "safe" endpoint does
                       unsafe things (e.g. ?confirm=true wipes data).
      - max_cost : a PER-RULE spend cap, independent of the global budget.
                   This is the real bound — the global budget only catches
                   volume, not a single oversized action.

    forbidden_targets (+ forbid_match, token by default) still reject
    specific dangerous tokens regardless of the allowlist.
    """
    action_type: str | None = None   # None = applies to all types
    allowed_targets: list[str] | None = None   # permit only these (match kind)
    forbidden_targets: list[str] | None = None  # deny these (forbid_match kind)
    match: str = "prefix"            # MatchKind for allowed_targets
    forbid_match: str = "token"      # MatchKind for forbidden_targets
    methods: list[str] | None = None  # allowed HTTP verbs (None = any)
    param_schema: dict | None = None  # JSON-schema-style constraint on params
    max_cost: float | None = None    # PER-RULE cost cap (tightest wins)
    requires_approval: bool = False  # this rule always needs approval
    allow_subactions: bool = True    # can this spawn sub-agents?


# ---------------------------------------------------------------------------
# Audit trail — immutable, append-only
# ---------------------------------------------------------------------------

class AuditTrail:
    """
    Immutable append-only log. Every event is hashed into a chain so
    tampering is detectable.

    This is the "blockchain-like" property without requiring an actual
    chain — the trust is in the integrity of the record. You can verify
    the chain is intact at any time.
    """

    def __init__(self):
        self._entries: list[dict] = []
        self._head_hash: str | None = None

    def append(self, event_type: str, agent_id: str, data: dict) -> str:
        """Append an event and return its hash."""
        entry = {
            "seq": len(self._entries),
            "event_type": event_type,
            "agent_id": agent_id,
            "data": data,
            "timestamp": time.time(),
            "prev_hash": self._head_hash,
        }
        entry["entry_hash"] = self._hash_entry(entry)
        self._entries.append(entry)
        self._head_hash = entry["entry_hash"]
        return entry["entry_hash"]

    def _hash_entry(self, entry: dict) -> str:
        raw = json.dumps({
            "seq": entry["seq"],
            "event_type": entry["event_type"],
            "agent_id": entry["agent_id"],
            "data": entry["data"],
            "timestamp": entry["timestamp"],
            "prev_hash": entry["prev_hash"],
        }, sort_keys=True, default=str)
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def verify_integrity(self) -> list[str]:
        """Return list of broken sequence numbers, empty if intact."""
        broken = []
        prev = None
        for e in self._entries:
            if e["prev_hash"] != prev:
                broken.append(e["seq"])
            prev = e["entry_hash"]
        return broken

    def query(
        self,
        agent_id: str | None = None,
        event_types: list[str] | None = None,
    ) -> list[dict]:
        """Query events by agent or type."""
        out = self._entries
        if agent_id:
            out = [e for e in out if e["agent_id"] == agent_id]
        if event_types:
            out = [e for e in out if e["event_type"] in event_types]
        return list(out)

    def get_full_history(self, agent_id: str) -> list[dict]:
        """Get all events for an agent."""
        return self.query(agent_id=agent_id)

    def reconstruct_sequence(self, agent_id: str) -> str:
        """Human-readable reconstruction of everything that happened."""
        entries = self.get_full_history(agent_id)
        lines = [f"=== Audit Trail: Agent {agent_id} ==="]
        lines.append(f"Total events: {len(entries)}")
        lines.append("")
        for e in entries:
            dt = datetime.fromtimestamp(e["timestamp"], timezone.utc)
            lines.append(f"[{dt.isoformat()}] {e['event_type']}")
            for k, v in e["data"].items():
                lines.append(f"    {k}: {v}")
            lines.append(f"    hash: {e['entry_hash']} (prev: {e['prev_hash']})")
            lines.append("")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Monitor — real-time visibility
# ---------------------------------------------------------------------------

class Monitor:
    """
    Emits events as the agent operates.

    Provides live state queries and anomaly detection hooks. Register
    callbacks to react to anomalies — blocked actions, critical actions
    not immediately allowed, cost spikes.
    """

    def __init__(self, audit: AuditTrail, agent_id: str):
        self.audit = audit
        self.agent_id = agent_id
        self.action_count = 0
        self.allowed_count = 0
        self.blocked_count = 0
        self.approval_pending = 0
        self.total_cost = 0.0
        self.last_action_time: float | None = None
        self.alert_callbacks: list[callable] = []
        self._start_time = time.time()

    def register_alert(self, cb: callable):
        """Register a callback for anomaly alerts."""
        self.alert_callbacks.append(cb)

    def record_action(self, result: ActionResult, request: ActionRequest):
        """Record an action outcome and check for anomalies."""
        self.action_count += 1
        self.last_action_time = time.time()

        if result.outcome == ActionOutcome.ALLOWED:
            self.allowed_count += 1
            self.total_cost += request.estimated_cost
            self.audit.append("action_allowed", self.agent_id, {
                "request_id": result.request_id,
                "action_type": request.action_type,
                "target": request.target,
                "cost": request.estimated_cost,
            })
        elif result.outcome == ActionOutcome.PENDING_APPROVAL:
            self.approval_pending += 1
            self.audit.append("action_pending_approval", self.agent_id, {
                "request_id": result.request_id,
                "action_type": request.action_type,
                "target": request.target,
                "requires_approval_for": result.requires_approval_for,
            })
        else:
            self.blocked_count += 1
            self.audit.append("action_blocked", self.agent_id, {
                "request_id": result.request_id,
                "action_type": request.action_type,
                "target": request.target,
                "reason": result.block_reason,
            })

        self._check_anomalies(result, request)

    def _check_anomalies(self, result: ActionResult, request: ActionRequest):
        """Check for anomalies and fire alert callbacks."""
        alerts: list[str] = []

        if result.outcome != ActionOutcome.ALLOWED:
            alerts.append(f"Action blocked: {result.block_reason}")

        if request.urgency == "critical" and result.outcome != ActionOutcome.ALLOWED:
            alerts.append("CRITICAL action was not immediately allowed")

        if request.estimated_cost > 0 and self.total_cost > 0:
            projected = self.total_cost + request.estimated_cost
            ratio = projected / max(self.total_cost, 1)
            if ratio > 2.0:
                alerts.append(
                    f"Single action cost ${request.estimated_cost:.2f} is >2x "
                    f"total prior spend (${self.total_cost:.2f})"
                )

        for alert in alerts:
            for cb in self.alert_callbacks:
                try:
                    cb(alert)
                except Exception:
                    pass  # don't let alert failures break the protocol

    def get_status(self) -> dict:
        """Get current monitor status."""
        return {
            "agent_id": self.agent_id,
            "action_count": self.action_count,
            "allowed": self.allowed_count,
            "blocked": self.blocked_count,
            "approval_pending": self.approval_pending,
            "total_cost": self.total_cost,
            "last_action": self.last_action_time,
            "uptime_seconds": time.time() - self._start_time,
        }

    def snapshot(self) -> str:
        """Human-readable status snapshot."""
        s = self.get_status()
        lines = [
            f"=== Live Monitor: Agent {self.agent_id} ===",
            f"Actions: {s['action_count']} total  "
            f"(allowed: {s['allowed']}, blocked: {s['blocked']}, "
            f"pending approval: {s['approval_pending']})",
            f"Total cost incurred: ${s['total_cost']:.2f}",
            f"Uptime: {s['uptime_seconds']:.0f}s",
            f"Last action: {datetime.fromtimestamp(s['last_action'], tz=timezone.utc).isoformat() if s['last_action'] else 'none'}",
            "",
        ]
        return "\n".join(lines)
