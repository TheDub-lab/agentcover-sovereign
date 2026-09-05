"""
Guard service — the surface a REAL agent calls.

This is the deployment shape: you (the user) write a config file with
least-privilege scope rules. The guard loads it, LINTS it before going
live (fail-closed: a broad rule means the guard refuses to start), and
exposes two surfaces over the SafetyProtocol + SafeSpendAgent:

  - HTTP  (any agent, any language, via stdlib http.server)
  - CLI   (safety-guard serve / check / pay / lint)

The agent NEVER touches the config or the rules. It only sends intents:
  POST /guard     {action_type, target, method?, params?, cost?}  -> allow/block
  POST /pay       {recipient, usd, resource?}                     -> gated payment
  POST /approve   {token, approved, approver}                     -> human sign-off
  POST /killswitch {reason}                                       -> kill switch
  GET  /audit     -> immutable decision log
  GET  /health    -> status + lint summary

Config is user-controlled. The agent can't widen its own scope. That's
the point: runtime enforcement the agent cannot negotiate around.

Run:
    python -m safety_protocol.guard_service --config examples/guard_config.json
    python examples/cli.py serve --config examples/guard_config.json
"""

from __future__ import annotations
import argparse
import json
import sys
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

# Allow running both as `python guard_service.py` and as a module.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from safety_protocol.core import (
    ActionRequest, AuditTrail, ScopeRule, ActionOutcome,
)
from safety_protocol.protocol import SafetyProtocol
from safety_protocol.payments import SafeSpendAgent, SimWallet
from safety_protocol.scope_linter import lint_rules, lint_report, Severity


# ---------------------------------------------------------------------------
# Config: user-controlled, linted on load (fail-closed)
# ---------------------------------------------------------------------------
def load_rules(cfg: dict) -> list[ScopeRule]:
    raw = cfg.get("scope_rules", [])
    rules = []
    for r in raw:
        rules.append(ScopeRule(
            action_type=r.get("action_type"),
            allowed_targets=r.get("allowed_targets"),
            forbidden_targets=r.get("forbidden_targets"),
            match=r.get("match", "exact"),
            forbid_match=r.get("forbid_match", "token"),
            methods=r.get("methods"),
            param_schema=r.get("param_schema"),
            max_cost=r.get("max_cost"),
            requires_approval=bool(r.get("requires_approval", False)),
            allow_subactions=bool(r.get("allow_subactions", True)),
        ))
    return rules


def build_protocol_from_config(cfg: dict) -> tuple[SafetyProtocol, list]:
    """Build the protocol from a user config. LINTS first, fails closed.

    Returns (protocol, findings). Raises SystemExit if the config is too
    broad to ship — the guard must not start with dangerous rules.
    """
    vocab = cfg.get("allowed_action_types", [])
    rules = load_rules(cfg)
    findings = lint_rules(rules, vocab)
    blocking = [f for f in findings
                if f.severity in (Severity.ERROR, Severity.WARN)]
    if blocking:
        # Fail closed: refuse to run with a broad/self-contradictory ruleset.
        raise SystemExit(
            "REFUSING TO START — scope rules failed lint:\n"
            + lint_report(findings)
        )
    audit = AuditTrail()
    protocol = SafetyProtocol(
        agent_id=cfg.get("agent_id", "guard-agent"),
        user_id=cfg.get("user_id", "user"),
        scope_rules=rules,
        budget_limit=cfg.get("budget_limit"),
        approval_threshold_cost=cfg.get("approval_threshold_cost", 10.0),
        audit=audit,
        allowed_action_types=vocab,
    )
    return protocol, findings


# ---------------------------------------------------------------------------
# The service
# ---------------------------------------------------------------------------
class GuardService:
    """Wraps SafetyProtocol (+ optional SafeSpendAgent) behind a clean API."""

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.protocol, self.findings = build_protocol_from_config(cfg)
        self.agent = None
        if "payment" in (self.protocol.allowed_action_types or []):
            self.agent = SafeSpendAgent(
                protocol=self.protocol, wallet=SimWallet())

    # -- the core gate (what every agent call funnels through) ----------
    def guard(self, action_type: str, target: str, method: str | None = None,
              params: dict | None = None, cost: float = 0.0) -> dict:
        req = ActionRequest(
            action_type=action_type, target=target, method=method,
            estimated_cost=cost, params=params or {},
        )
        res = self.protocol.execute(req)
        return {
            "outcome": res.outcome.value,
            "allowed": res.outcome == ActionOutcome.ALLOWED,
            "block_reason": res.block_reason,
            "requires_approval_for": res.requires_approval_for,
            "request_id": res.request_id,
        }

    def pay(self, recipient: str, usd: float, resource: str = "default") -> dict:
        if self.agent is None:
            return {"outcome": "blocked",
                    "block_reason": "payment not enabled in config",
                    "allowed": False}
        r = self.agent.direct_pay(recipient, usd, resource=resource)
        return {
            "outcome": r.outcome,
            "allowed": r.outcome in ("paid", "pending_approval"),
            "block_reason": r.reason,
            "approval_token": r.approval_token,
            "signed": bool(r.envelope),
        }

    def approve(self, token: str, approved: bool, approver: str) -> dict:
        ok = self.protocol.decide_approval(token, approved, approver)
        return {"approved": ok}

    def killswitch(self, reason: str) -> dict:
        self.protocol.engage_killswitch(reason)
        return {"engaged": True, "reason": reason}

    def audit(self) -> list[dict]:
        return self.protocol.audit.get_full_history(
            self.cfg.get("agent_id", "guard-agent"))

    def health(self) -> dict:
        m = self.protocol.monitor.get_status()
        return {
            "agent_id": self.cfg.get("agent_id", "guard-agent"),
            "user_id": self.protocol.user_id,
            "state": self.protocol._state.value,
            "lint": lint_report(self.findings),
            "monitor": m,
            "allowed_action_types": self.protocol.allowed_action_types,
        }


# ---------------------------------------------------------------------------
# HTTP surface (stdlib)
# ---------------------------------------------------------------------------
class _Handler(BaseHTTPRequestHandler):
    service: GuardService = None  # set by the server

    def log_message(self, *a):  # silence default stderr logging
        pass

    def _send(self, code: int, payload: dict):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> dict:
        n = int(self.headers.get("Content-Length", 0))
        if not n:
            return {}
        return json.loads(self.rfile.read(n).decode())

    def do_GET(self):
        if self.path == "/health":
            return self._send(200, self.service.health())
        if self.path == "/audit":
            return self._send(200, {"events": self.service.audit()})
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        b = self._body()
        if self.path == "/guard":
            return self._send(200, self.service.guard(
                b.get("action_type", ""), b.get("target", ""),
                method=b.get("method"), params=b.get("params"),
                cost=float(b.get("cost", 0.0))))
        if self.path == "/pay":
            return self._send(200, self.service.pay(
                b.get("recipient", ""), float(b.get("usd", 0.0)),
                resource=b.get("resource", "default")))
        if self.path == "/approve":
            return self._send(200, self.service.approve(
                b.get("token", ""), bool(b.get("approved", False)),
                b.get("approver", "user")))
        if self.path == "/killswitch":
            return self._send(200, self.service.killswitch(b.get("reason", "user")))
        return self._send(404, {"error": "not found"})


def serve(cfg_path: str, host: str = "127.0.0.1", port: int = 8080):
    with open(cfg_path) as f:
        cfg = json.load(f)
    svc = GuardService(cfg)  # may SystemExit if lint fails -> fail closed
    _Handler.service = svc
    httpd = ThreadingHTTPServer((host, port), _Handler)
    print(f"[guard] listening on http://{host}:{port}")
    print(f"[guard] agent={cfg.get('agent_id')} user={svc.protocol.user_id} "
          f"vocab={svc.protocol.allowed_action_types}")
    print(f"[guard] lint: {'BLOCK' if any(f.severity in (Severity.ERROR, Severity.WARN) for f in svc.findings) else 'clean'}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[guard] stopped")


def main():
    ap = argparse.ArgumentParser(description="Safety guard service")
    ap.add_argument("--config", required=True, help="user-controlled rules JSON")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8080)
    args = ap.parse_args()
    serve(args.config, args.host, args.port)


if __name__ == "__main__":
    main()
