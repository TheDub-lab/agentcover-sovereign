# SPDX-License-Identifier: MIT
"""Tests for the MIT log-shipping sender (safety_protocol.shipping)."""
import json

from safety_protocol.core import ActionOutcome, ActionRequest, ScopeRule
from safety_protocol.protocol import SafetyProtocol
from safety_protocol.shipping import (
    ZERO_HASH,
    LogShipper,
    Outbox,
    config_hash,
    params_digest,
    shipper_from_config,
    verify_event_hash,
)

RECEIVER = "https://logs.example.com"


def make_protocol(mode="enforce", approval_threshold=100.0, sinks=None):
    rules = [ScopeRule(
        action_type="api_call",
        allowed_targets=["https://api.research.example/v1/search"],
        match="exact",
        methods=["POST"],
        param_schema={
            "required": ["query"],
            "properties": {"query": {"type": "string"}},
            "additional_properties": False,
        },
        max_cost=5.0,
        rule_id="rule-0",
    )]
    return SafetyProtocol(
        agent_id="agent-001",
        user_id="alice",
        scope_rules=rules,
        budget_limit=10.0,
        approval_threshold_cost=approval_threshold,
        allowed_action_types=["api_call"],
        mode=mode,
        decision_sinks=sinks,
    )


class FakeTransport:
    """Records calls and returns a programmed (status, body)."""

    def __init__(self, respond):
        self.respond = respond
        self.calls = []

    def __call__(self, url, api_key, payload, timeout=10.0):
        self.calls.append((url, api_key, payload))
        return self.respond(url, api_key, payload)


def receipt(head_seq, head_hash):
    return {
        "agent_id": "agent-001",
        "head_seq": head_seq,
        "head_hash": head_hash,
        "received_at": "2026-10-14T18:03:12Z",
        "sig": "deadbeef",
        "sig_alg": "hmac-sha256",
    }


def make_shipper(tmp_path, log_params="none", transport=None, mode="enforce"):
    return LogShipper(
        receiver_url=RECEIVER,
        api_key="k-123",
        agent_id="agent-001",
        config_hash=config_hash({"agent_id": "agent-001"}),
        outbox_dir=str(tmp_path / "outbox"),
        log_params=log_params,
        mode=mode,
        transport=transport,
    )


def events_of(shipper):
    return shipper.outbox.pending(1000)


# -- canonical hashing ------------------------------------------------------

def test_event_hash_roundtrip_and_tamper(tmp_path):
    shipper = make_shipper(tmp_path)
    shipper.emit(
        ActionRequest(action_type="api_call", target="https://api.research.example/v1/search",
                      method="POST", params={"query": "hi"}),
        _result(ActionOutcome.ALLOWED),
    )
    ev = events_of(shipper)[0]
    assert verify_event_hash(ev) is True
    tampered = dict(ev, decision="denied")
    assert verify_event_hash(tampered) is False


def test_params_digest_is_canonical():
    a = params_digest({"b": 2, "a": 1})
    b = params_digest({"a": 1, "b": 2})
    assert a == b


# -- chain ------------------------------------------------------------------

def test_seq_starts_at_one_and_chains(tmp_path):
    shipper = make_shipper(tmp_path)
    p = make_protocol()
    for _ in range(2):
        p.execute(ActionRequest(
            action_type="api_call", target="https://api.research.example/v1/search",
            method="POST", params={"query": "hi"}))
    # p has no sinks; emit manually
    for req in [
        ActionRequest(action_type="api_call", target="x", params={"query": "1"}),
        ActionRequest(action_type="api_call", target="y", params={"query": "2"}),
    ]:
        shipper.emit(req, _result(ActionOutcome.ALLOWED))
    evs = events_of(shipper)
    assert [e["seq"] for e in evs] == [1, 2]
    assert evs[0]["prev_hash"] == ZERO_HASH
    assert evs[1]["prev_hash"] == evs[0]["hash"]


# -- privacy ----------------------------------------------------------------

def test_log_params_none_ships_no_raw_params(tmp_path):
    shipper = make_shipper(tmp_path, log_params="none")
    params = {"query": "sensitive", "api_key": "topsecret"}
    shipper.emit(
        ActionRequest(action_type="api_call", target="t", params=params),
        _result(ActionOutcome.ALLOWED),
    )
    ev = events_of(shipper)[0]
    assert "params" not in ev
    assert ev["param_keys"] == ["api_key", "query"]
    assert ev["params_digest"] == params_digest(params)


def test_log_params_redacted_masks_secret_keys(tmp_path):
    shipper = make_shipper(tmp_path, log_params="redacted")
    shipper.emit(
        ActionRequest(action_type="api_call", target="t",
                      params={"query": "keep", "api_key": "hide",
                              "auth_token": "hide2"}),
        _result(ActionOutcome.ALLOWED),
    )
    ev = events_of(shipper)[0]
    assert ev["params"]["query"] == "keep"
    assert ev["params"]["api_key"] == "***"
    assert ev["params"]["auth_token"] == "***"


# -- outbox durability ------------------------------------------------------

def test_outbox_survives_restart(tmp_path):
    shipper = make_shipper(tmp_path)
    shipper.emit(ActionRequest(action_type="api_call", target="a", params={"query": "1"}),
                 _result(ActionOutcome.ALLOWED))
    shipper.emit(ActionRequest(action_type="api_call", target="b", params={"query": "2"}),
                 _result(ActionOutcome.ALLOWED))
    head = events_of(shipper)[-1]["hash"]

    reopened = Outbox(str(tmp_path / "outbox"))
    assert reopened.next_seq() == 3
    assert reopened.head_hash() == head


# -- shipping / receipts ----------------------------------------------------

def test_flush_acknowledges_and_stores_receipt(tmp_path):
    transport = FakeTransport(lambda url, k, payload: (200, receipt(2, "h2")))
    shipper = make_shipper(tmp_path, transport=transport)
    for i in range(2):
        shipper.emit(ActionRequest(action_type="api_call", target=f"t{i}",
                                   params={"query": str(i)}),
                     _result(ActionOutcome.ALLOWED))
    r = shipper.flush_once()
    assert r["head_seq"] == 2
    assert shipper.outbox.acked_seq() == 2
    assert shipper.outbox.latest_receipt()["head_seq"] == 2
    assert shipper.outbox.pending(10) == []
    url, api_key, payload = transport.calls[0]
    assert url == RECEIVER + "/v1/events"
    assert api_key == "k-123"
    assert len(payload["events"]) == 2


def test_flush_on_409_rewinds_cursor(tmp_path):
    transport = FakeTransport(
        lambda url, k, payload: (409, {"error": "gap", "expected_seq": 1,
                                       "expected_prev_hash": ZERO_HASH}))
    shipper = make_shipper(tmp_path, transport=transport)
    for i in range(3):
        shipper.emit(ActionRequest(action_type="api_call", target=f"t{i}",
                                   params={"query": str(i)}),
                     _result(ActionOutcome.ALLOWED))
    assert shipper.flush_once() is None
    assert shipper.outbox.acked_seq() == 0
    assert len(shipper.outbox.pending(10)) == 3


def test_heartbeat_payload(tmp_path):
    transport = FakeTransport(lambda url, k, payload: (200, {"ok": True}))
    shipper = make_shipper(tmp_path, transport=transport)
    shipper.emit(ActionRequest(action_type="api_call", target="t", params={"query": "1"}),
                 _result(ActionOutcome.ALLOWED))
    assert shipper.send_heartbeat() is True
    url, _, payload = transport.calls[-1]
    assert url == RECEIVER + "/v1/heartbeat"
    assert payload["head_seq"] == 1
    assert payload["head_hash"] == events_of(shipper)[0]["hash"]
    assert payload["mode"] == "enforce"


def test_shipper_from_config_none_without_block():
    assert shipper_from_config({"agent_id": "a"}) is None
    s = shipper_from_config({
        "agent_id": "a",
        "shipping": {"receiver_url": RECEIVER, "api_key": "k"},
    })
    assert s is not None and s.receiver_url == RECEIVER


# -- integration with the protocol (sinks, shadow, approvals) ---------------

def test_decisions_are_shipped_via_sink(tmp_path):
    shipper = make_shipper(tmp_path)
    p = make_protocol(sinks=[shipper.emit])
    p.execute(ActionRequest(
        action_type="api_call", target="https://api.research.example/v1/search",
        method="POST", params={"query": "hi"}))
    p.execute(ActionRequest(
        action_type="api_call", target="https://api.research.example/v1/admin",
        method="POST", params={"query": "hi"}))
    evs = events_of(shipper)
    assert evs[0]["decision"] == "allowed"
    assert evs[0]["rule_id"] == "rule-0"
    assert evs[1]["decision"] == "denied"
    assert evs[1]["rule_id"] is None  # default-deny matches no rule


def test_shadow_mode_logs_policy_but_allows(tmp_path):
    shipper = make_shipper(tmp_path, mode="shadow")
    p = make_protocol(mode="shadow", sinks=[shipper.emit])
    res = p.execute(ActionRequest(
        action_type="api_call", target="https://evil.example/v1/admin",
        method="POST", params={"query": "hi"}))
    assert res.outcome == ActionOutcome.ALLOWED  # shadow allows
    ev = events_of(shipper)[0]
    assert ev["decision"] == "allowed"
    assert ev["policy_decision"] == "denied"
    assert ev["mode"] == "shadow"
    assert ev["reason"]  # the policy reason is preserved


def test_approval_decision_is_shipped(tmp_path):
    shipper = make_shipper(tmp_path)
    p = make_protocol(approval_threshold=0.0, sinks=[shipper.emit])
    res = p.execute(ActionRequest(
        action_type="api_call", target="https://api.research.example/v1/search",
        method="POST", params={"query": "hi"}))
    assert res.outcome == ActionOutcome.PENDING_APPROVAL
    token = res.requires_approval_for
    p.decide_approval(token, True, "bob", channel="control")
    evs = events_of(shipper)
    assert evs[0]["decision"] == "needs_approval"
    assert evs[1]["decision"] == "approved"
    assert evs[1]["policy_decision"] == "approved"
    # approver identity + channel are part of the externally verifiable event
    assert evs[1]["approver"] == "bob"
    assert evs[1]["approval_channel"] == "control"


def test_killswitch_is_shipped(tmp_path):
    shipper = make_shipper(tmp_path)
    p = make_protocol(sinks=[shipper.emit])
    p.engage_killswitch("incident")
    ev = events_of(shipper)[0]
    assert ev["decision"] == "killswitch"
    assert ev["action_type"] == "killswitch"


def _result(outcome):
    from safety_protocol.core import ActionResult
    return ActionResult("r-1", outcome, executed=outcome == ActionOutcome.ALLOWED)


def test_default_import_and_json_serialisable(tmp_path):
    shipper = make_shipper(tmp_path)
    ev = shipper.emit(ActionRequest(action_type="api_call", target="t",
                                    params={"query": "x"}),
                      _result(ActionOutcome.ALLOWED))
    json.dumps(ev)  # must be serialisable as-is
    assert ev["v"] == 1 and ev["event_id"]
