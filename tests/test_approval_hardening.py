# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Michael / TheDub-lab
"""Approval-token hardening tests (single-use, expiry, binding, attribution)."""

from safety_protocol.core import ActionOutcome, ActionRequest, ScopeRule
from safety_protocol.protocol import SafetyProtocol


def make_protocol(*, ttl_s=300.0, requires_approval=True):
    return SafetyProtocol(
        agent_id="agent-1",
        user_id="alice",
        scope_rules=[
            ScopeRule(
                action_type="api_call",
                allowed_targets=["https://api.example.com/v1/*"],
                match="glob",
                methods=["POST"],
                param_schema={"required": ["query"],
                              "properties": {"query": {"type": "string"}},
                              "additional_properties": False},
                requires_approval=requires_approval,
                rule_id="api",
            ),
        ],
        budget_limit=1000.0,
        approval_threshold_cost=1000.0,
        allowed_action_types=["api_call"],
        approval_ttl_s=ttl_s,
    )


def request(**over):
    base = {
        "action_type": "api_call",
        "target": "https://api.example.com/v1/search",
        "method": "POST",
        "params": {"query": "hi"},
    }
    base.update(over)
    return ActionRequest(**base)


def test_approved_intent_allows_retry_then_is_spent():
    p = make_protocol()
    res = p.execute(request())
    assert res.outcome == ActionOutcome.PENDING_APPROVAL
    token = res.requires_approval_for
    assert p.decide_approval(token, True, approver="alice") is True
    # the exact intent retries through
    assert p.execute(request()).outcome == ActionOutcome.ALLOWED


def test_token_is_single_use_after_expiry_window():
    p = make_protocol(ttl_s=0.0)
    res = p.execute(request())
    token = res.requires_approval_for
    # ttl 0 -> expires immediately
    assert p.decide_approval(token, True, approver="alice") is False
    assert p.audit.query(event_types=["approval_rejected"])


def test_expired_token_rejected():
    p = make_protocol(ttl_s=-1.0)
    token = p.request_approval(request())
    assert p.decide_approval(token, True, approver="alice") is False
    rejected = p.audit.query(event_types=["approval_rejected"])
    assert rejected and rejected[-1]["data"]["code"] == "expired"


def test_token_cannot_be_used_twice():
    p = make_protocol()
    token = p.request_approval(request())
    assert p.decide_approval(token, True, approver="alice") is True
    # the same token is spent — a second decision is refused and audited
    assert p.decide_approval(token, True, approver="alice") is False
    assert p.audit.query(event_types=["approval_unknown_token"])


def test_approval_is_bound_to_params():
    p = make_protocol()
    res = p.execute(request())
    token = res.requires_approval_for
    assert p.decide_approval(token, True, approver="alice") is True
    # approved for query "hi"; a different query must NOT be auto-allowed
    other = p.execute(request(params={"query": "something-else"}))
    assert other.outcome == ActionOutcome.PENDING_APPROVAL


def test_agent_cannot_approve_itself():
    p = make_protocol()
    res = p.execute(request())
    token = res.requires_approval_for
    assert p.decide_approval(token, True, approver="agent-1") is False
    rejected = p.audit.query(event_types=["approval_rejected"])
    assert rejected and rejected[-1]["data"]["code"] == "self_approval"


def test_same_session_approval_rejected():
    p = make_protocol()
    token = p.request_approval(request(), session_id="sess-9")
    assert p.decide_approval(token, True, approver="alice",
                             session_id="sess-9") is False
    rejected = p.audit.query(event_types=["approval_rejected"])
    assert rejected and rejected[-1]["data"]["code"] == "same_session"


def test_unknown_token_is_audited():
    p = make_protocol()
    assert p.decide_approval("nope", True, approver="alice") is False
    assert p.audit.query(event_types=["approval_unknown_token"])


def test_approver_and_channel_recorded_in_audit_chain():
    p = make_protocol()
    res = p.execute(request())
    token = res.requires_approval_for
    p.decide_approval(token, True, approver="carol", channel="telegram")
    dec = p.audit.query(event_types=["approval_decision"])[-1]
    assert dec["data"]["approver"] == "carol"
    assert dec["data"]["channel"] == "telegram"
    assert dec["data"]["digest"]


def test_approver_and_channel_land_in_result():
    # The decision-sink payload carries approver + channel so a shipper can
    # include them in the externally verifiable event (see test_shipping).
    events = []

    def sink(req, res, decision):
        events.append((req, res, decision))

    p = make_protocol()
    p.add_decision_sink(sink)
    res = p.execute(request())
    token = res.requires_approval_for
    p.decide_approval(token, True, approver="carol", channel="telegram")
    _, result, decision = events[-1]
    assert decision == "approved"
    assert result.execution_log["approver"] == "carol"
    assert result.execution_log["approval_channel"] == "telegram"


def test_approval_binds_to_the_covering_rule_not_the_action_type():
    # Two rules share action_type 'api_call'; only the write rule needs
    # approval. A call the read rule covers must NOT be held.
    p = SafetyProtocol(
        agent_id="agent-1",
        user_id="alice",
        scope_rules=[
            ScopeRule(action_type="api_call", allowed_targets=["read_thing"],
                      match="exact", methods=["POST"], rule_id="read",
                      requires_approval=False),
            ScopeRule(action_type="api_call", allowed_targets=["write_thing"],
                      match="exact", methods=["POST"], rule_id="write",
                      requires_approval=True),
        ],
        budget_limit=1000.0,
        approval_threshold_cost=1000.0,
        allowed_action_types=["api_call"],
    )
    read = p.execute(ActionRequest(action_type="api_call", target="read_thing",
                                   method="POST", params={}))
    assert read.outcome == ActionOutcome.ALLOWED
    write = p.execute(ActionRequest(action_type="api_call", target="write_thing",
                                    method="POST", params={}))
    assert write.outcome == ActionOutcome.PENDING_APPROVAL
