# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Michael / TheDub-lab
"""Tests for the Strands/LangChain tool-call guard (safety_protocol.integrations)."""

import asyncio

import pytest

from safety_protocol.core import ScopeRule
from safety_protocol.integrations import (
    evaluate_tool_call,
    guard_langchain_tool,
    guard_langchain_tools,
    guard_strands_tool,
    guard_strands_tools,
)
from safety_protocol.protocol import SafetyProtocol


def make_protocol(*, requires_approval=False, mode="enforce"):
    return SafetyProtocol(
        agent_id="agent-tools",
        user_id="alice",
        scope_rules=[
            ScopeRule(
                action_type="tool_call",
                allowed_targets=["read_file"],
                match="exact",
                methods=["TOOL"],
                param_schema={
                    "required": ["path"],
                    "properties": {"path": {"type": "string"}},
                    "additional_properties": False,
                },
                requires_approval=requires_approval,
                rule_id="tool-read",
            ),
        ],
        budget_limit=100.0,
        approval_threshold_cost=1000.0,
        allowed_action_types=["tool_call"],
        mode=mode,
    )


# -- core decision (no SDK) ------------------------------------------------


def test_evaluate_allowed():
    decision = evaluate_tool_call(make_protocol(), "read_file", {"path": "/tmp/a"})
    assert decision.allowed is True
    assert decision.kind == "allowed"
    assert decision.result.executed is True
    assert decision.metadata["kind"] == "allowed"
    assert decision.metadata["rule_id"] == "tool-read"


def test_evaluate_denied_target():
    decision = evaluate_tool_call(make_protocol(), "delete_all", {"path": "/tmp/a"})
    assert decision.allowed is False
    assert decision.kind == "denied"
    assert decision.text.startswith("Blocked by safety guard:")
    assert decision.metadata["decision"] == "blocked_scope"


def test_evaluate_denied_bad_method():
    decision = evaluate_tool_call(
        make_protocol(), "read_file", {"path": "/tmp/a"}, method="HTTP")
    assert decision.allowed is False
    assert decision.kind == "denied"


def test_evaluate_denied_extra_param():
    decision = evaluate_tool_call(
        make_protocol(), "read_file", {"path": "/tmp/a", "extra": "x"})
    assert decision.allowed is False


def test_evaluate_denied_budget():
    decision = evaluate_tool_call(
        make_protocol(), "read_file", {"path": "/tmp/a"}, cost=200.0)
    assert decision.allowed is False
    assert decision.metadata["decision"] == "blocked_budget"


def test_evaluate_approval():
    decision = evaluate_tool_call(
        make_protocol(requires_approval=True), "read_file", {"path": "/tmp/a"})
    assert decision.allowed is False
    assert decision.kind == "approval_required"
    assert decision.approval_token
    assert decision.metadata["approval_token"] == decision.approval_token


def test_evaluate_shadow_allows_but_records_policy():
    protocol = make_protocol(mode="shadow")
    decision = evaluate_tool_call(protocol, "delete_all", {"path": "/tmp/a"})
    assert decision.allowed is True
    assert decision.metadata["policy_decision"] == "blocked_scope"


def test_evaluate_killswitch():
    protocol = make_protocol()
    protocol.engage_killswitch("test freeze")
    decision = evaluate_tool_call(protocol, "read_file", {"path": "/tmp/a"})
    assert decision.allowed is False
    assert decision.metadata["decision"] == "blocked_killswitch"


# -- Strands ---------------------------------------------------------------


def _strands_tools():
    pytest.importorskip("strands")
    from strands import tool as strands_tool

    @strands_tool
    def read_file(path: str) -> str:
        """Read a file.

        Args:
            path: the path to read
        """
        return f"contents:{path}"

    @strands_tool
    def delete_all(path: str) -> str:
        """Delete everything.

        Args:
            path: the path to delete
        """
        return f"deleted:{path}"

    return read_file, delete_all


def test_strands_guarded_tool_preserves_spec():
    read_file, _ = _strands_tools()
    guarded = guard_strands_tool(read_file, make_protocol())
    assert guarded.tool_name == "read_file"
    assert guarded.tool_spec["inputSchema"] == read_file.tool_spec["inputSchema"]
    assert guarded.tool_spec["description"] == read_file.tool_spec["description"]


def test_strands_allowed_runs_tool_body():
    read_file, _ = _strands_tools()
    guarded = guard_strands_tool(read_file, make_protocol())
    assert guarded(path="/tmp/a") == "contents:/tmp/a"


def test_strands_denied_returns_error_dict():
    read_file, delete_all = _strands_tools()
    guarded = guard_strands_tool(delete_all, make_protocol())
    out = guarded(path="/tmp/a")
    assert isinstance(out, dict)
    assert out["status"] == "error"
    assert out["content"][0]["text"].startswith("Blocked by safety guard:")
    assert out["guard"]["decision"] == "blocked_scope"


def test_strands_denied_extra_param():
    read_file, _ = _strands_tools()
    guarded = guard_strands_tool(read_file, make_protocol())
    out = guarded(path="/tmp/a", extra="x")
    assert isinstance(out, dict) and out["status"] == "error"


def test_strands_stream_path_is_gated():
    _, delete_all = _strands_tools()
    guarded = guard_strands_tool(delete_all, make_protocol())

    async def run():
        tool_use = {"toolUseId": "t1", "name": "delete_all",
                    "input": {"path": "/tmp/a"}}
        events = [e async for e in guarded.stream(tool_use, {})]
        return events[-1].tool_result

    result = asyncio.run(run())
    assert result["status"] == "error"
    assert result["guard"]["kind"] == "denied"


def test_strands_stream_allowed_runs():
    read_file, _ = _strands_tools()
    guarded = guard_strands_tool(read_file, make_protocol())

    async def run():
        tool_use = {"toolUseId": "t1", "name": "read_file",
                    "input": {"path": "/tmp/a"}}
        events = [e async for e in guarded.stream(tool_use, {})]
        return events[-1].tool_result

    result = asyncio.run(run())
    assert result["status"] == "success"
    assert result["content"][0]["text"] == "contents:/tmp/a"


def test_strands_tools_mapper():
    read_file, delete_all = _strands_tools()
    guarded = guard_strands_tools([read_file, delete_all], make_protocol())
    assert [t.tool_name for t in guarded] == ["read_file", "delete_all"]


# -- LangChain -------------------------------------------------------------


def _langchain_tools():
    pytest.importorskip("langchain_core")
    from langchain_core.tools import tool as lc_tool

    @lc_tool
    def read_file(path: str) -> str:
        """Read a file."""
        return f"contents:{path}"

    @lc_tool
    def delete_all(path: str) -> str:
        """Delete everything."""
        return f"deleted:{path}"

    return read_file, delete_all


def test_langchain_guarded_tool_preserves_schema():
    read_file, _ = _langchain_tools()
    guarded = guard_langchain_tool(read_file, make_protocol())
    assert guarded.name == "read_file"
    props = guarded.args_schema.model_json_schema()["properties"]
    assert set(props) == {"path"}
    assert guarded.description == read_file.description


def test_langchain_allowed_runs_tool_body():
    read_file, _ = _langchain_tools()
    guarded = guard_langchain_tool(read_file, make_protocol())
    assert guarded.invoke({"path": "/tmp/a"}) == "contents:/tmp/a"


def test_langchain_async_allowed_runs_tool_body():
    read_file, _ = _langchain_tools()
    guarded = guard_langchain_tool(read_file, make_protocol())
    assert asyncio.run(guarded.ainvoke({"path": "/tmp/a"})) == "contents:/tmp/a"


def test_langchain_denied_returns_reason():
    _, delete_all = _langchain_tools()
    guarded = guard_langchain_tool(delete_all, make_protocol())
    out = guarded.invoke({"path": "/tmp/a"})
    assert out.startswith("Blocked by safety guard:")


def test_langchain_raise_on_deny():
    _, delete_all = _langchain_tools()
    from langchain_core.tools import ToolException

    guarded = guard_langchain_tool(delete_all, make_protocol(),
                                   raise_on_deny=True)
    with pytest.raises(ToolException):
        guarded.invoke({"path": "/tmp/a"})


def test_langchain_framework_validates_args_first():
    # LangChain validates against the tool schema before the guard runs, so a
    # call missing a required argument never reaches the guard — it is rejected
    # by the framework. (The guard still sees the normalized argument set.)
    read_file, _ = _langchain_tools()
    guarded = guard_langchain_tool(read_file, make_protocol())
    with pytest.raises(ValueError):
        guarded.invoke({})


def test_langchain_tools_mapper():
    read_file, delete_all = _langchain_tools()
    guarded = guard_langchain_tools([read_file, delete_all], make_protocol())
    assert [t.name for t in guarded] == ["read_file", "delete_all"]


# -- error handling --------------------------------------------------------


def test_missing_name_raises():
    with pytest.raises(TypeError):
        guard_strands_tool(lambda: None, make_protocol())
    with pytest.raises(TypeError):
        guard_langchain_tool(lambda: None, make_protocol())
