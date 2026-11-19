"""Tests for GuardService HTTP endpoints (/health, /pending, /approve, /killswitch)."""
from __future__ import annotations

import json
import threading
import urllib.request
from http.server import ThreadingHTTPServer

from safety_protocol.platform.guard_service import GuardService, _Handler


def _cfg() -> dict:
    return {
        "agent_id": "test-guard",
        "user_id": "operator",
        "budget_limit": 20.0,
        "approval_threshold_cost": 5.0,
        "allowed_action_types": ["api_call"],
        "scope_rules": [
            {
                "id": "search",
                "action_type": "api_call",
                "allowed_targets": ["https://api.example.com/v1/search"],
                "match": "exact",
                "methods": ["POST"],
                "param_schema": {
                    "required": ["query"],
                    "properties": {"query": {"type": "string", "maxLength": 100}},
                    "additional_properties": False,
                },
                "max_cost": 10.0,
                "requires_approval": False,
            }
        ],
    }


def _http_json(url: str, payload: dict | None = None) -> dict:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {"Content-Type": "application/json"} if data is not None else {}
    req = urllib.request.Request(
        url, data=data, headers=headers, method="POST" if data is not None else "GET"
    )
    with urllib.request.urlopen(req, timeout=2.0) as resp:
        return json.loads(resp.read().decode("utf-8"))


def test_guard_service_health_budget_and_pending_flow():
    svc = GuardService(_cfg(), start_shipper=False)
    handler_cls = type("_TestGuardHandler", (_Handler,), {"service": svc})
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{port}"
    try:
        health = _http_json(f"{base}/health")
        assert health["agent_id"] == "test-guard"
        assert health["budget_limit"] == 20.0
        assert health["state"] == "active"

        # Trigger an approval-gated action (cost >= approval_threshold_cost)
        res = _http_json(
            f"{base}/guard",
            {
                "action_type": "api_call",
                "target": "https://api.example.com/v1/search",
                "method": "POST",
                "params": {"query": "expensive"},
                "cost": 6.0,
            },
        )
        assert res["outcome"] == "pending_approval"
        token = res["requires_approval_for"]
        assert token

        # GET /pending exposes the held request
        pending = _http_json(f"{base}/pending")
        assert len(pending["pending"]) == 1
        assert pending["pending"][0]["token"] == token

        # POST /approve resolves it with operator reason
        dec = _http_json(
            f"{base}/approve",
            {
                "token": token,
                "approved": True,
                "approver": "thedub-lab",
                "reason": "Approved from Omarchy widget",
            },
        )
        assert dec["approved"] is True
        assert _http_json(f"{base}/pending")["pending"] == []
    finally:
        httpd.shutdown()
        httpd.server_close()
        svc.close()
