# SPDX-License-Identifier: BUSL-1.1
"""Tests for the BSL log receiver (safety_protocol.platform.receiver)."""
import hashlib

import pytest

pytest.importorskip("safety_protocol.platform")

from safety_protocol.core import ActionOutcome, ActionRequest, ScopeRule
from safety_protocol.platform.receiver import HAVE_ED25519, Receiver, Store, verify_receipt
from safety_protocol.protocol import SafetyProtocol
from safety_protocol.shipping import ZERO_HASH, LogShipper, config_hash

ADMIN = "admin-secret"


def make_receiver():
    store = Store(":memory:")
    return Receiver(store, admin_key=ADMIN)


def make_agent(rx, agent_id="agent-001"):
    rx.dispatch("POST", "/v1/admin/clients", {}, ADMIN, {"client_id": "acme"})
    _, body = rx.dispatch("POST", "/v1/admin/agents", {}, ADMIN,
                          {"agent_id": agent_id, "client_id": "acme"})
    return body["api_key"]


def make_protocol(mode="enforce", sinks=None):
    rules = [ScopeRule(
        action_type="api_call",
        allowed_targets=["https://api.research.example/v1/search"],
        match="exact",
        methods=["POST"],
        param_schema={"required": ["query"], "properties": {"query": {"type": "string"}},
                      "additional_properties": False},
        max_cost=5.0,
        rule_id="rule-0",
    )]
    return SafetyProtocol(
        agent_id="agent-001", user_id="alice", scope_rules=rules,
        budget_limit=10.0, approval_threshold_cost=100.0,
        allowed_action_types=["api_call"], mode=mode, decision_sinks=sinks)


def shipper_for(rx, api_key, tmp_path):
    """A shipper whose transport posts straight into the in-process receiver."""
    def transport(url, key, payload, timeout=10.0):
        if url.endswith("/v1/events"):
            return rx.dispatch("POST", "/v1/events", {}, key, payload)
        if url.endswith("/v1/heartbeat"):
            return rx.dispatch("POST", "/v1/heartbeat", {}, key, payload)
        return 404, {"error": "not found"}
    return LogShipper(
        receiver_url="http://receiver.local", api_key=api_key, agent_id="agent-001",
        config_hash=config_hash({"agent_id": "agent-001"}),
        outbox_dir=str(tmp_path / "outbox"), transport=transport)


# -- admin / auth -----------------------------------------------------------

def test_admin_requires_admin_key():
    rx = make_receiver()
    assert rx.dispatch("POST", "/v1/admin/clients", {}, "wrong", {"client_id": "x"})[0] == 401
    assert rx.dispatch("POST", "/v1/admin/agents", {}, "", {"agent_id": "a"})[0] == 401


def test_create_agent_returns_key_once_and_stores_hash():
    rx = make_receiver()
    api_key = make_agent(rx)
    assert api_key
    agent = rx.store.get_agent("agent-001")
    assert agent is not None
    assert api_key not in agent["api_key_hash"]  # only the hash is stored
    assert rx.store.get_agent_by_key_hash(
        hashlib.sha256(api_key.encode()).hexdigest())["agent_id"] == "agent-001"


def test_ingest_rejects_bad_key():
    rx = make_receiver()
    make_agent(rx)
    code, _ = rx.dispatch("POST", "/v1/events", {}, "nope", {"agent_id": "agent-001", "events": []})
    assert code == 401


# -- ingest / chain ---------------------------------------------------------

def test_ingest_and_receipt(tmp_path):
    rx = make_receiver()
    key = make_agent(rx)
    shipper = shipper_for(rx, key, tmp_path)
    p = make_protocol(sinks=[shipper.emit])
    for _ in range(3):
        p.execute(ActionRequest(
            action_type="api_call", target="https://api.research.example/v1/search",
            method="POST", params={"query": "hi"}))
    receipt = shipper.flush_once()
    assert receipt is not None
    assert receipt["head_seq"] == 3
    assert shipper.outbox.acked_seq() == 3

    # receipt verifies under the receiver's own key
    if HAVE_ED25519:
        assert verify_receipt(receipt, public_key_hex=rx.signer.public_key_hex()) is True
    else:
        assert verify_receipt(receipt, hmac_secret_hex=rx.signer.private_key_hex()) is True

    assert rx.store.verify_chain("agent-001")["ok"] is True
    assert rx.store.count_events("agent-001") == 3


def test_receipt_verify_direct(tmp_path):
    rx = make_receiver()
    key = make_agent(rx)
    shipper = shipper_for(rx, key, tmp_path)
    p = make_protocol(sinks=[shipper.emit])
    p.execute(ActionRequest(
        action_type="api_call", target="https://api.research.example/v1/search",
        method="POST", params={"query": "hi"}))
    receipt = shipper.flush_once()
    assert rx.signer.verify(
        {k: receipt[k] for k in ("agent_id", "head_seq", "head_hash", "received_at")},
        receipt["sig"]) is True
    # tampering the head invalidates the receipt
    bad = dict(receipt, head_hash="0" * 64)
    assert rx.signer.verify(
        {k: bad[k] for k in ("agent_id", "head_seq", "head_hash", "received_at")},
        bad["sig"]) is False


def test_ingest_is_idempotent(tmp_path):
    rx = make_receiver()
    key = make_agent(rx)
    shipper = shipper_for(rx, key, tmp_path)
    p = make_protocol(sinks=[shipper.emit])
    p.execute(ActionRequest(
        action_type="api_call", target="https://api.research.example/v1/search",
        method="POST", params={"query": "hi"}))
    events = shipper.outbox.pending(10)
    assert rx.dispatch("POST", "/v1/events", {}, key,
                       {"agent_id": "agent-001", "events": events})[0] == 200
    # resending the exact batch is accepted silently, count stays 1
    assert rx.dispatch("POST", "/v1/events", {}, key,
                       {"agent_id": "agent-001", "events": events})[0] == 200
    assert rx.store.count_events("agent-001") == 1


def test_fork_is_rejected(tmp_path):
    rx = make_receiver()
    key = make_agent(rx)
    shipper = shipper_for(rx, key, tmp_path)
    p = make_protocol(sinks=[shipper.emit])
    p.execute(ActionRequest(
        action_type="api_call", target="https://api.research.example/v1/search",
        method="POST", params={"query": "hi"}))
    ev = shipper.outbox.pending(10)[0]
    rx.dispatch("POST", "/v1/events", {}, key, {"agent_id": "agent-001", "events": [ev]})

    forked = dict(ev, ts="2026-01-01T00:00:00Z")
    from safety_protocol.shipping import hash_event
    forked["hash"] = hash_event(forked)
    code, body = rx.dispatch("POST", "/v1/events", {}, key,
                             {"agent_id": "agent-001", "events": [forked]})
    assert code == 409
    assert body["error"] == "fork"


def test_gap_reports_expected(tmp_path):
    rx = make_receiver()
    key = make_agent(rx)
    shipper = shipper_for(rx, key, tmp_path)
    p = make_protocol(sinks=[shipper.emit])
    for _ in range(2):
        p.execute(ActionRequest(
            action_type="api_call", target="https://api.research.example/v1/search",
            method="POST", params={"query": "hi"}))
    evs = shipper.outbox.pending(10)
    # deliver only the SECOND event -> gap (expected seq 1)
    code, body = rx.dispatch("POST", "/v1/events", {}, key,
                             {"agent_id": "agent-001", "events": [evs[1]]})
    assert code == 409
    assert body["expected_seq"] == 1
    assert body["expected_prev_hash"] == ZERO_HASH


def test_batch_too_large_and_empty(tmp_path):
    rx = make_receiver()
    key = make_agent(rx)
    assert rx.dispatch("POST", "/v1/events", {}, key,
                       {"agent_id": "agent-001", "events": []})[0] == 400
    assert rx.dispatch("POST", "/v1/events", {}, key,
                       {"agent_id": "agent-001", "events": [{}] * 101})[0] == 400


# -- query / verify / report / heartbeat ------------------------------------

def test_verify_detects_tamper(tmp_path):
    rx = make_receiver()
    key = make_agent(rx)
    shipper = shipper_for(rx, key, tmp_path)
    p = make_protocol(sinks=[shipper.emit])
    for _ in range(2):
        p.execute(ActionRequest(
            action_type="api_call", target="https://api.research.example/v1/search",
            method="POST", params={"query": "hi"}))
    shipper.flush_once()
    assert rx.store.verify_chain("agent-001")["ok"] is True

    # tamper directly in the DB (the receiver's own store) -> chain breaks
    p_ev = rx.store.get_event("agent-001", 1)
    import json
    payload = json.loads(p_ev["payload"])
    payload["decision"] = "denied"
    rx.store.conn.execute("UPDATE events SET payload=? WHERE agent_id=? AND seq=?",
                          (json.dumps(payload), "agent-001", 1))
    rx.store.conn.commit()
    result = rx.store.verify_chain("agent-001")
    assert result["ok"] is False
    assert result["first_break"] == 1


def test_list_events_and_report(tmp_path):
    rx = make_receiver()
    key = make_agent(rx)
    shipper = shipper_for(rx, key, tmp_path)
    p = make_protocol(sinks=[shipper.emit])
    p.execute(ActionRequest(
        action_type="api_call", target="https://api.research.example/v1/search",
        method="POST", params={"query": "hi"}))
    p.execute(ActionRequest(
        action_type="api_call", target="https://evil.example/v1/admin",
        method="POST", params={"query": "hi"}))
    shipper.flush_once()

    code, body = rx.dispatch("GET", "/v1/agents/agent-001/events", {},
                             key, {})
    assert code == 200 and body["count"] == 2

    code, body = rx.dispatch("GET", "/v1/agents/agent-001/events",
                             {"decision": ["denied"]}, key, {})
    assert body["count"] == 1
    assert body["events"][0]["decision"] == "denied"

    code, body = rx.dispatch("GET", "/v1/agents/agent-001/report", {}, key, {})
    assert body["event_count"] == 2
    assert body["by_decision"]["allowed"] == 1
    assert body["by_decision"]["denied"] == 1
    assert body["latest_receipt"]["head_seq"] == 2

    code, body = rx.dispatch("GET", "/v1/agents/agent-001/verify", {}, key, {})
    assert code == 200 and body["ok"] is True


def test_heartbeat_stored(tmp_path):
    rx = make_receiver()
    key = make_agent(rx)
    code, _ = rx.dispatch("POST", "/v1/heartbeat", {}, key, {
        "agent_id": "agent-001", "ts": "2026-10-14T18:00:00Z",
        "head_seq": 0, "head_hash": ZERO_HASH, "mode": "enforce",
        "config_hash": "abc", "guard_version": "0.4.0"})
    assert code == 200
    hb = rx.store.latest_heartbeat("agent-001")
    assert hb["mode"] == "enforce"
    assert hb["head_hash"] == ZERO_HASH


def test_cross_agent_key_rejected(tmp_path):
    rx = make_receiver()
    key = make_agent(rx, "agent-001")
    make_agent(rx, "agent-002")
    code, _ = rx.dispatch("GET", "/v1/agents/agent-002/events", {}, key, {})
    assert code == 403


def test_unknown_route_404():
    rx = make_receiver()
    assert rx.dispatch("GET", "/nope", {}, "", {})[0] == 404


def test_action_outcome_import_smoke():
    # keep the ActionOutcome import exercised
    assert ActionOutcome.ALLOWED.value == "allowed"
