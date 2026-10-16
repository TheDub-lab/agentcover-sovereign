# MCP proxy

`safety-guard mcp-proxy` sits between an MCP client and a real MCP server and
evaluates **every tool call** before it reaches the server.

```text
MCP client  <--stdio JSON-RPC-->  safety-guard mcp-proxy  <--stdio JSON-RPC-->  MCP server
        (Claude Desktop / agent host)                              (filesystem, DB, …)
```

This is shape (2) of the [threat model](../README.md#threat-model--non-goals):
the guard is the only path to the tool server, so the agent has no way to reach
the tool except through the guard. Zero extra dependencies — the proxy speaks
newline-delimited JSON-RPC, which is the MCP stdio transport.

## Quickstart

```bash
safety-guard mcp-proxy --config guard_config.json -- \
    npx -y @modelcontextprotocol/server-filesystem /data
```

Point your MCP client at `safety-guard mcp-proxy --config … -- <server cmd>`
instead of the server directly. The client sees a normal MCP server (the
`initialize` reply is annotated with `serverInfo.name = safety-protocol-guard`
and the real upstream name under `serverInfo.upstream`).

## Config

An MCP scope rule binds the tool name and its arguments:

```jsonc
{
  "agent_id": "mcp-agent",
  "user_id": "alice",
  "mode": "enforce",                        // or "shadow"
  "allowed_action_types": ["mcp_tool_call"], // deny every other verb
  "budget_limit": 10.0,
  "approval_threshold_cost": 5.0,
  "scope_rules": [
    {
      "id": "mcp-read",
      "action_type": "mcp_tool_call",
      "allowed_targets": ["read_file", "list_directory"],  // tool names
      "match": "exact",                     // exact | prefix | glob | regex
      "methods": ["MCP"],                   // the synthetic transport verb
      "param_schema": {                     // the tool's argument schema
        "required": ["path"],
        "properties": {"path": {"type": "string"}},
        "additional_properties": false
      },
      "requires_approval": false
    },
    {
      "id": "mcp-write",
      "action_type": "mcp_tool_call",
      "allowed_targets": ["write_file"],
      "match": "exact",
      "methods": ["MCP"],
      "param_schema": {"required": ["path"], "properties": {"path": {"type": "string"}}},
      "requires_approval": true             // held for human sign-off
    }
  ],
  "mcp": {                                   // optional
    "action_type": "mcp_tool_call",          // default
    "method": "MCP",                         // default
    "cost_per_call": 0.0,                    // set >0 to make budget apply
    "server_name": "safety-protocol-guard"   // announced to the client
  },
  "shipping": {                              // optional — ship decisions
    "receiver_url": "https://logs.example.com",
    "api_key": "per-agent key"
  }
}
```

`methods` and `param_schema` are **required** for any rule with an
`allowed_targets` list — the linter will not let it start otherwise
(`NO_METHOD`, `NO_PARAM_SCHEMA` are fail-closed WARNs). That is deliberate:
a tool whose arguments are unvalidated is a "safe" tool doing unsafe things.
Use `"additional_properties": true` for a tool whose arguments are inherently
open, and say so in a comment.

## What is intercepted

| Message | Behavior |
| ------- | -------- |
| `tools/call` | **Intercepted.** Evaluated by the guard; denied calls never reach upstream. |
| `initialize` | Forwarded; `serverInfo` rewritten to identify the guard. |
| `tools/list`, `resources/*`, `prompts/*`, `completion/*`, `logging/*`, `ping` | Forwarded unchanged. |
| Notifications (`notifications/*`) | Forwarded unchanged. |
| Server-initiated requests (e.g. `sampling/createMessage`) | Forwarded; ids rewritten so they cannot collide with client ids. |
| Anything the guard cannot parse | Forwarded (the guard fails open on malformed JSON, closed on policy). |

## Decision → MCP result

| Guard outcome | What the client gets |
| ------------- | -------------------- |
| `allowed` (and shadow-mode allows) | The upstream result, passed through. |
| `blocked_scope` / `blocked_budget` / `blocked_killswitch` | A tool error: `isError: true`, `content[0].text` = reason, `structuredContent.guard` = `{kind, decision, policy_decision, rule_id, request_id}`. Nothing is sent upstream. |
| `pending_approval` | A tool error with `kind: "approval_required"` and the approval token. Nothing is sent upstream; retry after approval. |

`structuredContent.guard.policy_decision` differs from `decision` in **shadow**
mode: the call is forwarded, and the record shows what policy would have
denied.

## Approvals

A held call returns its approval token. An operator decides out of band — over
the control endpoint (localhost only, on by default at `127.0.0.1:8788`), or
in-process via `SafetyProtocol.decide_approval(token, approved, approver)`.

| Method | Path | Body | Purpose |
| ------ | ---- | ---- | ------- |
| GET | `/pending` | — | What is waiting for a human decision |
| POST | `/approve` | `{token, approved?, approver?, reason?}` | Decide one |
| GET | `/health` | — | `{ok, mode}` |

```bash
safety-guard mcp-proxy --config guard_config.json --control-port 8788 -- <server>
curl -s localhost:8788/pending
curl -s -XPOST localhost:8788/approve -d '{"token":"<tok>","approver":"alice"}'
```

Use `--no-control` to disable it, `--control-host`/`--control-port` to move it.
It binds `127.0.0.1` by default and is not an authentication surface — anyone
who can reach it can approve, so keep it on loopback.

The approval must be decided by something the **agent cannot reach**. If you
expose the control endpoint to the agent's network, approval becomes
decorative (see [threat model](../README.md#threat-model--non-goals)).

## Log shipping

If the config has a `shipping` block, every tool-call decision is shipped to the
receiver as a normal event (`action_type` = `mcp_tool_call`, `target` = the tool
name, `params` = the arguments, subject to `log_params`). The outbox is durable;
a receiver outage never blocks tool calls.

## Limitations (read these)

- **stdio only.** The upstream is a subprocess. A streamable-HTTP MCP server
  needs an `mcp-proxy`-style HTTP relay in front of it (roadmap).
- **Cost is declared, not measured.** `mcp.cost_per_call` is what the budget
  sees. It does not know what the tool actually costs.
- **It gates the call, not the tool's side effects after success.** Once a call
  is allowed, whatever the upstream server does with it is the upstream's
  business; a tool that mutates more than its arguments suggest is not caught
  (that is a `param_schema` and tool-design problem).
- **`tools/list` is not filtered.** The agent can see tools it is not allowed to
  call; calls to them are denied. Hiding them is a roadmap item.
- **Approvals are fail-closed.** With no control endpoint reachable, a
  `requires_approval` tool simply cannot be called.
