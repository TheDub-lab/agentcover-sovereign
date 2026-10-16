# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Michael / TheDub-lab
"""
Framework integrations — gate agent tool calls through the safety guard.

The guard is the authority on what an agent may do. These adapters put it in
front of *in-process* tool calls, so an agent built on Strands or LangChain has
every tool invocation evaluated (binding, scope, budget, approval, kill switch)
**before** the tool body runs. A denied call never executes; the agent receives
a normal tool error carrying the guard's reason.

    agent -> guarded tool -> SafetyProtocol.execute -> (allow) tool body
                                                     (deny)  error result

Policy mapping — each tool call becomes one guard action:

    action_type = "tool_call"   (configurable)
    target      = the tool name
    method      = "TOOL"        (configurable)
    params      = the tool arguments
    cost        = cost         (default 0 — set it to make budget bite)

A scope rule that permits a tool therefore looks like:

    {
      "id": "read-local",
      "action_type": "tool_call",
      "allowed_targets": ["read_file"],
      "match": "exact",
      "methods": ["TOOL"],
      "param_schema": {
        "required": ["path"],
        "properties": {"path": {"type": "string"}},
        "additional_properties": false
      },
      "requires_approval": false
    }

If you already route MCP tool calls through ``safety-guard mcp-proxy`` you can
set ``action_type="mcp_tool_call"`` here to share one rule set.

This module is import-light: the Strands/LangChain SDKs are imported lazily
inside the guard builders, so the SDK itself never depends on them.
"""
from __future__ import annotations

import functools
from dataclasses import dataclass, field

from .core import ActionOutcome, ActionRequest, ActionResult

ALLOWED = "allowed"
DENIED = "denied"
APPROVAL_REQUIRED = "approval_required"

GUARD_KEY = "guard"
"""Key under which guard metadata travels with an error result."""


@dataclass
class ToolDecision:
    """The guard's verdict for one tool call."""

    allowed: bool
    kind: str
    text: str
    result: ActionResult
    metadata: dict = field(default_factory=dict)

    @property
    def request_id(self) -> str:
        return self.result.request_id

    @property
    def approval_token(self):
        return self.result.requires_approval_for


def evaluate_tool_call(
    protocol,
    tool_name,
    arguments,
    *,
    action_type: str = "tool_call",
    method: str = "TOOL",
    cost: float = 0.0,
) -> ToolDecision:
    """Evaluate a single tool call against ``protocol``.

    Returns a :class:`ToolDecision`. ``allowed`` is true only when the action
    ran (in shadow mode a would-be block is still allowed through, matching
    ``SafetyProtocol.execute``).
    """
    params = dict(arguments) if isinstance(arguments, dict) else {}
    request = ActionRequest(
        action_type=action_type,
        target=str(tool_name),
        method=method,
        params=params,
        estimated_cost=float(cost or 0.0),
    )
    result = protocol.execute(request)
    allowed = result.outcome == ActionOutcome.ALLOWED and result.executed

    metadata = {
        "kind": ALLOWED if allowed else None,
        "decision": result.outcome.value,
        "policy_decision": result.execution_log.get("policy_outcome"),
        "rule_id": result.execution_log.get("rule_id"),
        "request_id": result.request_id,
        "approval_token": result.requires_approval_for,
        "action_type": action_type,
        "target": str(tool_name),
    }

    if allowed:
        metadata["kind"] = ALLOWED
        return ToolDecision(True, ALLOWED, "", result, metadata)

    if result.outcome == ActionOutcome.PENDING_APPROVAL:
        token = result.requires_approval_for
        metadata["kind"] = APPROVAL_REQUIRED
        text = (
            "Blocked by safety guard: this tool call requires human approval "
            f"(token {token}). An operator must approve it, then the call can "
            "be retried."
        )
        return ToolDecision(False, APPROVAL_REQUIRED, text, result, metadata)

    metadata["kind"] = DENIED
    reason = result.block_reason or "denied by policy"
    return ToolDecision(False, DENIED, f"Blocked by safety guard: {reason}",
                        result, metadata)


# ---------------------------------------------------------------------------
# Strands Agents
# ---------------------------------------------------------------------------


def guard_strands_tool(
    tool_obj,
    protocol,
    *,
    action_type: str = "tool_call",
    method: str = "TOOL",
    cost: float = 0.0,
    name: str | None = None,
):
    """Wrap a Strands ``@tool`` in the safety guard.

    ``tool_obj`` is a tool produced by ``strands.tool`` (a
    ``DecoratedFunctionTool``). The returned tool has the same name,
    description and input schema; its body is gated. A blocked call yields a
    normal Strands tool error whose content is the guard's reason, plus a
    ``guard`` block carrying the decision metadata.

    Usage::

        from strands import Agent, tool
        from safety_protocol.integrations import guard_strands_tool

        @tool
        def read_file(path: str) -> str:
            \"\"\"Read a file.
            Args:
                path: the path to read
            \"\"\"
            return open(path).read()

        agent = Agent(tools=[guard_strands_tool(read_file, protocol)])
    """
    raw = getattr(tool_obj, "__wrapped__", None)
    tool_name = name or getattr(tool_obj, "tool_name", None)
    if not tool_name:
        raise TypeError(
            "guard_strands_tool expects a tool from strands.tool "
            "(it needs a .tool_name)"
        )

    try:
        from strands import tool as _strands_tool
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise ImportError(
            "guard_strands_tool requires the 'strands-agents' package "
            "(pip install strands-agents)"
        ) from exc

    if raw is None or not callable(raw):
        if not callable(tool_obj):
            raise TypeError(
                "guard_strands_tool expects a callable strands tool"
            )
        raw = tool_obj

    spec = getattr(tool_obj, "tool_spec", None)

    @functools.wraps(raw)
    def guarded(*args, **kwargs):
        decision = evaluate_tool_call(
            protocol, tool_name, kwargs,
            action_type=action_type, method=method, cost=cost,
        )
        if not decision.allowed:
            return {
                "status": "error",
                "content": [{"text": decision.text}],
                GUARD_KEY: decision.metadata,
            }
        return raw(*args, **kwargs)

    if isinstance(spec, dict) and "description" in spec and "inputSchema" in spec:
        return _strands_tool(
            name=tool_name,
            description=spec["description"],
            inputSchema=spec["inputSchema"],
        )(guarded)
    return _strands_tool(name=tool_name)(guarded)


def guard_strands_tools(tools, protocol, **kwargs):
    """Map :func:`guard_strands_tool` over an iterable of Strands tools."""
    return [guard_strands_tool(t, protocol, **kwargs) for t in tools]


# ---------------------------------------------------------------------------
# LangChain
# ---------------------------------------------------------------------------


def guard_langchain_tool(
    tool_obj,
    protocol,
    *,
    action_type: str = "tool_call",
    method: str = "TOOL",
    cost: float = 0.0,
    name: str | None = None,
    raise_on_deny: bool = False,
):
    """Wrap a LangChain tool in the safety guard.

    ``tool_obj`` is any ``BaseTool`` (e.g. one built with
    ``langchain_core.tools.tool``). The returned tool keeps the original's
    name, description, schema and ``return_direct``; invocation is gated. A
    blocked call returns the guard's reason as the tool output, or raises
    ``ToolException`` when ``raise_on_deny=True``.

    Usage::

        from langchain_core.tools import tool
        from safety_protocol.integrations import guard_langchain_tool

        @tool
        def read_file(path: str) -> str:
            \"\"\"Read a file.\"\"\"
            return open(path).read()

        safe_read = guard_langchain_tool(read_file, protocol)
        agent = create_react_agent(llm, [safe_read])
    """
    tool_name = name or getattr(tool_obj, "name", None)
    if not tool_name:
        raise TypeError(
            "guard_langchain_tool expects a LangChain tool (it needs a .name)"
        )
    if not hasattr(tool_obj, "invoke"):
        raise TypeError("guard_langchain_tool expects a LangChain BaseTool")

    try:
        from langchain_core.tools import StructuredTool, ToolException
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise ImportError(
            "guard_langchain_tool requires 'langchain-core' "
            "(pip install langchain-core)"
        ) from exc

    description = getattr(tool_obj, "description", "") or ""
    args_schema = getattr(tool_obj, "args_schema", None)
    return_direct = bool(getattr(tool_obj, "return_direct", False))

    def _decide(kwargs: dict) -> ToolDecision:
        return evaluate_tool_call(
            protocol, tool_name, kwargs,
            action_type=action_type, method=method, cost=cost,
        )

    def _blocked(decision: ToolDecision):
        if raise_on_deny:
            raise ToolException(decision.text)
        return decision.text

    def guarded(*args, **kwargs):
        decision = _decide(kwargs)
        if not decision.allowed:
            return _blocked(decision)
        return tool_obj.invoke(kwargs)

    async def async_guarded(*args, **kwargs):
        decision = _decide(kwargs)
        if not decision.allowed:
            return _blocked(decision)
        return await tool_obj.ainvoke(kwargs)

    raw = getattr(tool_obj, "func", None) or getattr(
        tool_obj, "coroutine", None)
    if raw is not None:
        functools.wraps(raw)(guarded)
        if args_schema is None:
            functools.wraps(raw)(async_guarded)

    return StructuredTool.from_function(
        func=guarded,
        coroutine=async_guarded,
        name=tool_name,
        description=description,
        args_schema=args_schema,
        return_direct=return_direct,
    )


def guard_langchain_tools(tools, protocol, **kwargs):
    """Map :func:`guard_langchain_tool` over an iterable of LangChain tools."""
    return [guard_langchain_tool(t, protocol, **kwargs) for t in tools]
