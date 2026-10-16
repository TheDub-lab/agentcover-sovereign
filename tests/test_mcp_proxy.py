# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Michael / TheDub-lab
"""Tests for the MIT MCP proxy adapter (safety_protocol.mcp_proxy)."""

import json
import sys
import urllib.error
import urllib.request

from safety_protocol.core import ScopeRule
from safety_protocol.mcp_proxy import (
    MCPProxy,
    normalize_resource_uri,
    proxy_from_config,
    run_stdio,
    start_control_server,
)
from safety_protocol.protocol import SafetyProtocol


def make_protocol(*, requires_approval=False, mode="enforce"):
    return SafetyProtocol(
        agent_id="agent-mcp",
        user_id="alice",
        scope_rules=[
            ScopeRule(
                action_type="mcp_tool_call",
                allowed_targets=["read_file", "list_directory"],
                match="exact",
                methods=["MCP"],
                param_schema={
                    "required": ["path"],
                    "properties": {"path": {"type": "string"}},
                    "additional_properties": False,
                },
                requires_approval=requires_approval,
                rule_id="mcp-read",
            ),
        ],
        budget_limit=100.0,
        approval_threshold_cost=1000.0,
        allowed_action_types=["mcp_tool_call"],
        mode=mode,
    )


def make_proxy(*, requires_approval=False, mode="enforce"):
    return MCPProxy(make_protocol(
        requires_approval=requires_approval, mode=mode))


def call_msg(tool, args, mid=1):
    return {
        "jsonrpc": "2.0",
        "id": mid,
        "method": "tools/call",
        "params": {"name": tool, "arguments": args},
    }


# -- passthrough -----------------------------------------------------------


def test_initialize_forwarded_and_patched():
    proxy = make_proxy()
    to_client, to_upstream = proxy.handle_client_message({
        "jsonrpc": "2.0", "id": 0, "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                   "clientInfo": {"name": "test", "version": "1"}},
    })
    assert to_client == [] and len(to_upstream) == 1
    forwarded_id = to_upstream[0]["id"]

    client_msgs = proxy.handle_upstream_message({
        "jsonrpc": "2.0", "id": forwarded_id,
        "result": {"protocolVersion": "2025-06-18",
                   "capabilities": {"tools": {}},
                   "serverInfo": {"name": "filesystem", "version": "9"}},
    })
    assert len(client_msgs) == 1
    info = client_msgs[0]["result"]["serverInfo"]
    assert client_msgs[0]["id"] == 0
    assert info["name"] == "safety-protocol-guard"
    assert info["upstream"] == "filesystem"


def test_tools_list_passes_through_unchanged():
    proxy = make_proxy()
    _, to_upstream = proxy.handle_client_message({
        "jsonrpc": "2.0", "id": 7, "method": "tools/list", "params": {}})
    assert len(to_upstream) == 1
    forwarded = to_upstream[0]
    client_msgs = proxy.handle_upstream_message({
        "jsonrpc": "2.0", "id": forwarded["id"],
        "result": {"tools": [{"name": "read_file"}]}})
    assert client_msgs[0]["id"] == 7
    assert client_msgs[0]["result"]["tools"] == [{"name": "read_file"}]


def test_notification_forwarded_verbatim():
    proxy = make_proxy()
    to_client, to_upstream = proxy.handle_client_message({
        "jsonrpc": "2.0", "method": "notifications/initialized"})
    assert to_client == []
    assert to_upstream == [
        {"jsonrpc": "2.0", "method": "notifications/initialized"}]


# -- enforcement -----------------------------------------------------------


def test_allowed_tool_call_forwarded_and_response_returned():
    proxy = make_proxy()
    to_client, to_upstream = proxy.handle_client_message(
        call_msg("read_file", {"path": "/data/report.txt"}))
    assert to_client == []
    assert len(to_upstream) == 1
    forwarded = to_upstream[0]
    assert forwarded["params"]["name"] == "read_file"

    client_msgs = proxy.handle_upstream_message({
        "jsonrpc": "2.0", "id": forwarded["id"],
        "result": {"content": [{"type": "text", "text": "hello"}]}})
    assert client_msgs[0]["id"] == 1
    assert client_msgs[0]["result"]["content"][0]["text"] == "hello"


def test_denied_tool_never_reaches_upstream():
    proxy = make_proxy()
    to_client, to_upstream = proxy.handle_client_message(
        call_msg("write_file", {"path": "/etc/passwd"}))
    assert to_upstream == []
    assert len(to_client) == 1
    err = to_client[0]
    assert err["id"] == 1
    assert err["result"]["isError"] is True
    assert "Blocked by safety guard" in err["result"]["content"][0]["text"]
    guard = err["result"]["structuredContent"]["guard"]
    assert guard["kind"] == "denied"
    assert guard["decision"] == "blocked_scope"


def test_param_schema_violation_denied():
    proxy = make_proxy()
    to_client, to_upstream = proxy.handle_client_message(
        call_msg("read_file", {"path": 123}))
    assert to_upstream == []
    assert to_client[0]["result"]["isError"] is True


def test_unknown_action_vocab_denied_without_upstream():
    protocol = SafetyProtocol(
        agent_id="a", user_id="u", scope_rules=[],
        allowed_action_types=["api_call"])
    proxy = MCPProxy(protocol)
    to_client, to_upstream = proxy.handle_client_message(
        call_msg("read_file", {"path": "/x"}))
    assert to_upstream == []
    assert to_client[0]["result"]["isError"] is True


def test_killswitch_blocks_every_call():
    proxy = make_proxy()
    proxy.protocol.engage_killswitch("incident")
    to_client, to_upstream = proxy.handle_client_message(
        call_msg("read_file", {"path": "/data/x"}))
    assert to_upstream == []
    assert to_client[0]["result"]["isError"] is True
    assert (to_client[0]["result"]["structuredContent"]["guard"]["decision"]
            == "blocked_killswitch")


def test_shadow_mode_forwards_but_flags_policy_deny():
    proxy = make_proxy(mode="shadow")
    seen = []
    proxy.protocol.add_decision_sink(
        lambda req, res, decision: seen.append(res))
    to_client, to_upstream = proxy.handle_client_message(
        call_msg("write_file", {"path": "/etc/passwd"}))
    # shadow mode: policy would deny, but the call is forwarded
    assert len(to_upstream) == 1
    assert to_client == []
    assert seen and seen[0].execution_log["policy_outcome"] == "blocked_scope"
    assert seen[0].execution_log["shadow"] is True


def test_decision_sink_receives_allowed_event():
    proxy = make_proxy()
    seen = []
    proxy.protocol.add_decision_sink(lambda req, res, d: seen.append((req, res)))
    proxy.handle_client_message(call_msg("read_file", {"path": "/data/a"}))
    assert len(seen) == 1
    req, res = seen[0]
    assert req.action_type == "mcp_tool_call"
    assert req.target == "read_file"
    assert req.method == "MCP"
    assert res.outcome.value == "allowed"
    assert res.execution_log["rule_id"] == "mcp-read"


# -- approval flow ---------------------------------------------------------


def test_approval_required_returns_token_then_retry_allowed():
    proxy = make_proxy(requires_approval=True)
    to_client, to_upstream = proxy.handle_client_message(
        call_msg("read_file", {"path": "/data/x"}))
    assert to_upstream == []
    guard = to_client[0]["result"]["structuredContent"]["guard"]
    assert guard["kind"] == "approval_required"
    token = guard["approval_token"]
    assert token

    # pending approval is visible to an operator
    pending = proxy.protocol.get_pending_approvals()
    assert [p["token"] for p in pending] == [token]

    assert proxy.protocol.decide_approval(token, True, approver="alice") is True

    # retry of the same intent is now allowed through
    _, to_upstream2 = proxy.handle_client_message(
        call_msg("read_file", {"path": "/data/x"}))
    assert len(to_upstream2) == 1


# -- id collision / server-initiated requests ------------------------------


def test_server_initiated_request_ids_do_not_collide():
    proxy = make_proxy()
    # client request id 1 -> forwarded with a proxy id
    _, to_upstream = proxy.handle_client_message(
        call_msg("read_file", {"path": "/data/x"}, mid=1))
    upstream_id = to_upstream[0]["id"]

    # server initiates its own request with id 1 (collision risk)
    client_msgs = proxy.handle_upstream_message({
        "jsonrpc": "2.0", "id": 1, "method": "sampling/createMessage",
        "params": {}})
    server_req = client_msgs[0]
    assert server_req["id"] != 1  # rewritten

    # client answers the server-initiated request
    _, reply_up = proxy.handle_client_message({
        "jsonrpc": "2.0", "id": server_req["id"], "result": {"role": "user"}})
    assert reply_up[0]["id"] == 1

    # and the original call response still maps back to client id 1
    resp = proxy.handle_upstream_message({
        "jsonrpc": "2.0", "id": upstream_id, "result": {"content": []}})
    assert resp[0]["id"] == 1


# -- config-driven build ---------------------------------------------------


def test_proxy_from_config_builds_and_enforces():
    cfg = {
        "agent_id": "cfg-agent",
        "user_id": "u",
        "allowed_action_types": ["mcp_tool_call"],
        "scope_rules": [{
            "id": "r1",
            "action_type": "mcp_tool_call",
            "allowed_targets": ["read_file"],
            "match": "exact",
            "methods": ["MCP"],
            "param_schema": {"required": ["path"],
                             "properties": {"path": {"type": "string"}},
                             "additional_properties": False},
        }],
        "mcp": {"cost_per_call": 0.0},
    }
    _, proxy, shipper, findings = proxy_from_config(cfg, start_shipper=False)
    assert shipper is None
    assert proxy.protocol.agent_id == "cfg-agent"
    _, to_upstream = proxy.handle_client_message(
        call_msg("read_file", {"path": "/x"}))
    assert len(to_upstream) == 1
    client, up = proxy.handle_client_message(call_msg("write_file", {"path": "/x"}))
    assert up == [] and client[0]["result"]["isError"] is True


# -- real stdio plumbing (subprocess upstream) -----------------------------

_FAKE_UPSTREAM = r"""
import json, sys
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    msg = json.loads(line)
    if msg.get("method") == "tools/call":
        reply = {"jsonrpc": "2.0", "id": msg["id"],
                 "result": {"content": [{"type": "text",
                            "text": "ran " + msg["params"]["name"]}]}}
    else:
        reply = {"jsonrpc": "2.0", "id": msg["id"], "result": {}}
    sys.stdout.write(json.dumps(reply) + "\n")
    sys.stdout.flush()
"""


def test_run_stdio_round_trip_with_real_subprocess():
    proxy = make_proxy()
    upstream = [sys.executable, "-c", _FAKE_UPSTREAM]
    lines = [
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                    "params": {"name": "read_file", "arguments": {"path": "/a"}}}),
        json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                    "params": {"name": "write_file", "arguments": {"path": "/b"}}}),
    ]
    import io

    out = io.StringIO()
    run_stdio(proxy, upstream,
              client_in=iter([ln + "\n" for ln in lines]), client_out=out)
    replies = [json.loads(ln)
               for ln in out.getvalue().splitlines() if ln.strip()]
    by_id = {r["id"]: r for r in replies}
    assert "ran read_file" in by_id[1]["result"]["content"][0]["text"]
    assert by_id[2]["result"]["isError"] is True


# -- resource URI normalization --------------------------------------------


def test_normalize_collapses_dot_segments():
    norm, err = normalize_resource_uri("file:///data/reports/./q3/../q4.csv")
    assert err is None
    assert norm == "file:///data/reports/q4.csv"


def test_normalize_rejects_traversal_at_root():
    norm, err = normalize_resource_uri("file:///../../etc/passwd")
    assert norm is None
    assert "escapes" in err


def test_normalize_rejects_single_encoded_traversal_that_escapes():
    # %2e%2e decodes to '..' — collapses, and escaping the root is rejected.
    norm, err = normalize_resource_uri("file:///%2e%2e/%2e%2e/etc/passwd")
    assert norm is None
    assert "escapes" in err


def test_normalize_rejects_double_encoding():
    norm, err = normalize_resource_uri("file:///data/%252e%252e/secret")
    assert norm is None
    assert "double-encoded" in err


def test_normalize_lowercases_scheme_but_preserves_path_case():
    norm, err = normalize_resource_uri("FILE:///Data/Reports/Q3.CSV")
    assert err is None
    assert norm == "file:///Data/Reports/Q3.CSV"


def test_normalize_rejects_non_allowlisted_scheme():
    norm, err = normalize_resource_uri("http://example.com/x")
    assert norm is None
    assert "not allowed" in err


def test_normalize_preserves_trailing_slash():
    assert normalize_resource_uri("file:///data/reports/")[0] == \
        "file:///data/reports/"
    assert normalize_resource_uri("file:///data/reports")[0] == \
        "file:///data/reports"


def test_normalize_treats_localhost_and_empty_file_host_alike():
    assert normalize_resource_uri("file://localhost/data/x")[0] == \
        normalize_resource_uri("file:///data/x")[0] == "file:///data/x"


def test_normalize_rejects_empty_and_non_hierarchical():
    assert normalize_resource_uri("")[1]
    assert normalize_resource_uri("data/x")[1]


# -- resource gating -------------------------------------------------------


def make_resource_protocol(*, mode="enforce"):
    schema = {"required": ["uri"],
              "properties": {"uri": {"type": "string"}},
              "additional_properties": False}
    return SafetyProtocol(
        agent_id="agent-mcp",
        user_id="alice",
        scope_rules=[
            ScopeRule(action_type="mcp_resource_read",
                      allowed_targets=["file:///data/reports/*"],
                      match="glob", methods=["MCP"], param_schema=schema,
                      rule_id="read-reports"),
            ScopeRule(action_type="mcp_resource_subscribe",
                      allowed_targets=["file:///data/reports/*"],
                      match="glob", methods=["MCP"], param_schema=schema,
                      rule_id="sub-reports"),
        ],
        allowed_action_types=["mcp_resource_read", "mcp_resource_subscribe"],
        mode=mode,
    )


def read_msg(uri, mid=1, method="resources/read"):
    return {"jsonrpc": "2.0", "id": mid, "method": method,
            "params": {"uri": uri}}


def test_resource_read_allowed_is_normalized_and_forwarded():
    proxy = MCPProxy(make_resource_protocol())
    to_client, to_upstream = proxy.handle_client_message(
        read_msg("file:///data/reports/./q3.csv"))
    assert to_client == []
    assert len(to_upstream) == 1
    assert to_upstream[0]["params"]["uri"] == "file:///data/reports/q3.csv"


def test_resource_read_out_of_scope_never_reaches_upstream():
    proxy = MCPProxy(make_resource_protocol())
    to_client, to_upstream = proxy.handle_client_message(
        read_msg("file:///etc/passwd"))
    assert to_upstream == []
    assert to_client[0]["result"]["isError"] is True
    guard = to_client[0]["result"]["structuredContent"]["guard"]
    assert guard["kind"] == "denied"
    assert guard["decision"] == "blocked_scope"


def test_resource_glob_does_not_overmatch_sibling_directory():
    proxy = MCPProxy(make_resource_protocol())
    # /data/reports-private must NOT be covered by file:///data/reports/*
    to_client, to_upstream = proxy.handle_client_message(
        read_msg("file:///data/reports-private/secret.txt"))
    assert to_upstream == []
    assert to_client[0]["result"]["isError"] is True


def test_resource_subscribe_is_gated_with_its_own_verb():
    proxy = MCPProxy(make_resource_protocol())
    _, up = proxy.handle_client_message(
        read_msg("file:///data/reports/q3.csv", method="resources/subscribe"))
    assert len(up) == 1
    seen = []
    proxy.protocol.add_decision_sink(lambda r, res, d: seen.append(r))
    proxy.handle_client_message(
        read_msg("file:///etc/x", mid=2, method="resources/subscribe"))
    assert seen[0].action_type == "mcp_resource_subscribe"


def test_malformed_resource_uri_hard_denied_even_in_shadow():
    proxy = MCPProxy(make_resource_protocol(mode="shadow"))
    to_client, to_upstream = proxy.handle_client_message(
        read_msg("file:///%2e%2e/%2e%2e/etc/passwd"))
    # Shadow mode does not forward a URI that fails normalization.
    assert to_upstream == []
    assert to_client[0]["result"]["isError"] is True
    text = to_client[0]["result"]["content"][0]["text"]
    assert "resource uri rejected" in text


def test_shadow_mode_forwards_out_of_scope_resource_but_flags():
    proxy = MCPProxy(make_resource_protocol(mode="shadow"))
    seen = []
    proxy.protocol.add_decision_sink(lambda r, res, d: seen.append(res))
    to_client, to_upstream = proxy.handle_client_message(
        read_msg("file:///etc/passwd"))
    assert len(to_upstream) == 1
    assert seen[0].execution_log["policy_outcome"] == "blocked_scope"
    assert seen[0].execution_log["shadow"] is True


def test_gate_resources_false_forwards_untouched():
    proxy = MCPProxy(make_resource_protocol(), gate_resources=False)
    to_client, to_upstream = proxy.handle_client_message(
        read_msg("file:///etc/passwd"))
    assert to_client == []
    assert to_upstream[0]["params"]["uri"] == "file:///etc/passwd"


def test_proxy_from_config_resource_gating_default_on():
    cfg = {
        "agent_id": "cfg", "user_id": "u",
        "allowed_action_types": ["mcp_resource_read"],
        "scope_rules": [{
            "id": "r1", "action_type": "mcp_resource_read",
            "allowed_targets": ["file:///data/*"], "match": "glob",
            "methods": ["MCP"],
            "param_schema": {"required": ["uri"],
                             "properties": {"uri": {"type": "string"}},
                             "additional_properties": False},
        }],
        "mcp": {"action_type": "mcp_tool_call"},
    }
    _, proxy, _, _ = proxy_from_config(cfg, start_shipper=False)
    assert proxy.gate_resources is True
    _, up = proxy.handle_client_message(read_msg("file:///data/a"))
    assert len(up) == 1


def test_proxy_from_config_resources_ungated_is_audited():
    cfg = {
        "agent_id": "cfg", "user_id": "u",
        "allowed_action_types": ["mcp_tool_call"],
        "scope_rules": [{
            "id": "r1", "action_type": "mcp_tool_call",
            "allowed_targets": ["read_file"], "match": "exact",
            "methods": ["MCP"],
            "param_schema": {"required": ["path"],
                             "properties": {"path": {"type": "string"}},
                             "additional_properties": False},
        }],
        "mcp": {"gate_resources": False},
    }
    protocol, proxy, _, _ = proxy_from_config(cfg, start_shipper=False)
    assert proxy.gate_resources is False
    assert protocol.audit.query(event_types=["resources_ungated"])


# -- control endpoint: approver secret -------------------------------------


def _http(method, url, *, headers=None, body=None):
    req = urllib.request.Request(
        url, method=method, data=body, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def test_control_endpoint_requires_secret_and_audits_failure():
    proxy = make_proxy(requires_approval=True)
    httpd = start_control_server(proxy, "127.0.0.1", 0, secret="s3cret")
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    try:
        code, _ = _http("POST", base + "/approve", body=b'{"token":"x"}')
        assert code == 401
        assert proxy.protocol.audit.query(event_types=["approval_auth_failed"])
        # authorized but unknown token -> 404, not 401
        code2, _ = _http("POST", base + "/approve",
                         headers={"X-Approver-Secret": "s3cret"},
                         body=b'{"token":"x"}')
        assert code2 == 404
        # bearer form is accepted too
        code3, _ = _http("POST", base + "/approve",
                         headers={"Authorization": "Bearer s3cret"},
                         body=b'{"token":"x"}')
        assert code3 == 404
        # /health is open; /pending is not
        assert _http("GET", base + "/health")[0] == 200
        assert _http("GET", base + "/pending")[0] == 401
        assert _http("GET", base + "/pending",
                     headers={"X-Approver-Secret": "s3cret"})[0] == 200
    finally:
        httpd.shutdown()


def test_control_endpoint_approves_with_secret_and_records_channel():
    proxy = make_proxy(requires_approval=True)
    _, to_upstream = proxy.handle_client_message(
        call_msg("read_file", {"path": "/data/x"}))
    assert to_upstream == []
    token = proxy.protocol.get_pending_approvals()[0]["token"]

    httpd = start_control_server(proxy, "127.0.0.1", 0, secret="s3cret")
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    try:
        body = json.dumps({"token": token, "approver": "dana"}).encode()
        code, payload = _http("POST", base + "/approve",
                              headers={"X-Approver-Secret": "s3cret",
                                       "Content-Type": "application/json"},
                              body=body)
        assert code == 200 and payload["ok"] is True
    finally:
        httpd.shutdown()
    dec = proxy.protocol.audit.query(event_types=["approval_decision"])[-1]
    assert dec["data"]["approver"] == "dana"
    assert dec["data"]["channel"] == "control"

    # the agent's retry now goes through
    _, retry_up = proxy.handle_client_message(
        call_msg("read_file", {"path": "/data/x"}))
    assert len(retry_up) == 1


def test_control_endpoint_refuses_non_loopback_without_secret():
    proxy = make_proxy()
    try:
        start_control_server(proxy, "0.0.0.0", 0, secret=None,
                             require_secret=True)
    except ValueError as e:
        assert "non-loopback" in str(e)
    else:  # pragma: no cover
        raise AssertionError("expected ValueError")
