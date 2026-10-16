# Strands & LangChain wrappers

Gate **in-process** tool calls (no MCP server) so every tool the agent invokes
is evaluated by the guard *before* the tool body runs.

```text
agent  ->  guarded tool  ->  SafetyProtocol.execute  ->  allow: tool body
                                                     ->  deny:  tool error
```

This is shape (2) of the [threat model](../README.md#threat-model--non-goals):
the wrapped tool object is the agent's only handle on the capability, so the
agent cannot reach the tool except through the guard. If your agent calls tools
over MCP instead, use [`safety-guard mcp-proxy`](mcp-proxy.md); the two can
share one rule set (see [Config](#config)).

## Install

The wrappers import the SDKs lazily, so the core SDK stays dependency-free.
Install the extra you need:

```bash
pip install "safety-protocol[strands]"     # strands-agents
pip install "safety-protocol[langchain]"   # langchain-core
```

## Strands

```python
from strands import Agent, tool
from safety_protocol.config import build_protocol_from_config
from safety_protocol.integrations import guard_strands_tool

protocol = build_protocol_from_config("tool_guard_config.json")

@tool
def read_file(path: str) -> str:
    """Read a file.

    Args:
        path: the path to read
    """
    return open(path).read()

agent = Agent(tools=[guard_strands_tool(read_file, protocol)])
```

Use `guard_strands_tools(tools, protocol)` to map over a list.

## LangChain

```python
from langchain_core.tools import tool as lc_tool
from safety_protocol.integrations import guard_langchain_tool

@lc_tool
def delete_all(path: str) -> str:
    """Delete everything under path."""
    return do_delete(path)

safe_delete = guard_langchain_tool(delete_all, protocol)
```

Use `guard_langchain_tools(tools, protocol)` to map over a list, and
`raise_on_deny=True` to raise `ToolException` instead of returning the reason as
the tool output.

## What the wrapper keeps

Both wrappers preserve the tool's **name, description and input schema**, so the
model sees no change — only the execution path is gated.

- **Strands.** The returned tool is a `strands.tool` with the original's
  `description` and `inputSchema`. A blocked call is a normal Strands tool error
  (`status: "error"`), so the agent can react; a `guard` key on the result
  carries the decision metadata.
- **LangChain.** The returned tool is a `StructuredTool` with the original's
  `name`, `description`, `args_schema` and `return_direct`. A blocked call
  returns the reason as the tool output (or raises `ToolException`).

## Config

Each tool call becomes one guard action:

| Field | Value |
| ----- | ----- |
| `action_type` | `tool_call` (configurable) |
| `target` | the tool name |
| `method` | `TOOL` (configurable) |
| `params` | the tool arguments |
| `estimated_cost` | `cost` (default `0.0`) |

A rule that permits a tool:

```jsonc
{
  "id": "tool-read",
  "action_type": "tool_call",
  "allowed_targets": ["read_file", "list_directory"],  // tool names
  "match": "exact",                    // exact | prefix | glob | regex
  "methods": ["TOOL"],                 // the synthetic transport verb
  "param_schema": {                    // the tool's arguments
    "required": ["path"],
    "properties": {"path": {"type": "string"}},
    "additional_properties": false
  },
  "requires_approval": false
}
```

`methods` and `param_schema` are **required** for any rule with an
`allowed_targets` list — the linter will not let it start otherwise
(`NO_METHOD`, `NO_PARAM_SCHEMA` are fail-closed WARNs). See
[`examples/tool_guard_config.json`](../examples/tool_guard_config.json).

To share one rule set with the MCP proxy, pass `action_type="mcp_tool_call"`,
`method="MCP"` to the guard builders (or set `action_type`/`method` per project).

## Decision → tool result

| Guard outcome | Strands | LangChain |
| ------------- | ------- | --------- |
| `allowed` (and shadow-mode allows) | Tool body runs; its value is returned. | Tool body runs; its value is returned. |
| `blocked_scope` / `blocked_budget` / `blocked_killswitch` | Error dict `{status: "error", content: [{text}], guard: {…}}`. Tool body never runs. | The reason string (`raise_on_deny=True` → `ToolException`). Tool body never runs. |
| `pending_approval` | Error dict with `requires_approval` text and the token in `guard.approval_token`. Retry after approval. | The reason string naming the token. Retry after approval. |

The `guard` metadata is the same shape the MCP proxy returns under
`structuredContent.guard`: `{kind, decision, policy_decision, rule_id,
request_id, approval_token, action_type, target}` — so logs line up across the
two shapes.

`policy_decision` differs from `decision` in **shadow** mode: the call is
allowed through, and the record shows what policy would have denied.

## Approvals

Identical to the MCP proxy: a held call returns its approval token; an operator
decides out of band via `SafetyProtocol.decide_approval(token, approved,
approver)` (or the guard service's `/approve`), then the agent retries. The
approver must be a channel the **agent cannot reach**, or approval is
decorative.

## Limitations (read these)

- **The wrapper gates the call, not the tool's side effects after success.**
  Once a call is allowed, whatever the tool body does is the tool's business;
  a tool that touches more than its arguments suggest is a `param_schema` and
  tool-design problem.
- **LangChain validates before the guard.** `langchain-core` validates the
  call against the tool's `args_schema` and passes the normalized arguments to
  the guard, so unknown arguments are dropped by the framework rather than
  caught by `additional_properties: false`. Scope still enforces target,
  method, budget, approval, and required/typed parameters. Strands behaves the
  same on the agent path (input is validated against the tool schema first).
- **The tool must be reachable only through the wrapper.** Guarding a tool
  while also handing the agent the original (or a second credential) is
  advisory — see the assumption in the threat model.
- **Cost is declared, not measured.** `cost=` is what the budget sees.
- **Not a sandbox.** It does not constrain what the tool body can do once it
  runs; it constrains *whether* it runs.
