# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Michael / TheDub-lab
"""Tests for MCP-config linting and non-blocking findings."""

from safety_protocol.config import build_protocol_from_config
from safety_protocol.scope_linter import (
    Severity,
    blocking_findings,
    lint_mcp_config,
)


def test_ungated_resources_is_loud_but_not_blocking():
    findings = lint_mcp_config({"gate_resources": False})
    assert len(findings) == 1
    assert findings[0].code == "MCP_RESOURCES_UNGATED"
    assert findings[0].severity == Severity.WARN
    assert findings[0].blocking is False
    assert blocking_findings(findings) == []


def test_empty_scheme_list_is_blocking():
    findings = lint_mcp_config({"allowed_uri_schemes": []})
    assert [f.code for f in findings] == ["MCP_URI_SCHEMES_EMPTY"]
    assert blocking_findings(findings)


def test_missing_mcp_block_is_not_a_finding():
    assert lint_mcp_config(None) == []


def _cfg(mcp):
    return {
        "agent_id": "a", "user_id": "u",
        "allowed_action_types": ["mcp_tool_call"],
        "scope_rules": [{
            "id": "r1", "action_type": "mcp_tool_call",
            "allowed_targets": ["read_file"], "match": "exact",
            "methods": ["MCP"],
            "param_schema": {"required": ["path"],
                             "properties": {"path": {"type": "string"}},
                             "additional_properties": False},
        }],
        "mcp": mcp,
    }


def test_gate_resources_false_does_not_fail_closed_at_build():
    # Non-blocking: the guard still builds (used for shadow rollout).
    protocol, findings = build_protocol_from_config(_cfg({"gate_resources": False}))
    assert protocol is not None
    assert any(f.code == "MCP_RESOURCES_UNGATED" for f in findings)


def test_invalid_schemes_fail_closed_at_build():
    import pytest

    with pytest.raises(SystemExit):
        build_protocol_from_config(_cfg({"allowed_uri_schemes": []}))
