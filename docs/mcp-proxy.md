# MCP proxy

`safety-guard mcp-proxy` sits between an MCP client and a real MCP server and
evaluates **every tool call** — and, by default, **every resource read and
subscribe** — before it reaches the server.

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
  "allowed_action_types": ["mcp_tool_call", "mcp_resource_read"], // deny every other verb
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
      "param_schema": {"required": ["path", "content"],
                       "properties": {"path": {"type": "string"},
                                      "content": {"type": "string"}}},
      "requires_approval": true             // held for human sign-off
    },
    {
      "id": "mcp-read-reports",
      "action_type": "mcp_resource_read",    // resources/read
      "allowed_targets": ["file:///data/reports/*"], // the resource URI
      "match": "glob",
      "methods": ["MCP"],
      "param_schema": {
        "required": ["uri"],
        "properties": {"uri": {"type": "string"}},
        "additional_properties": false
      },
      "requires_approval": false
    }
  ],
  "mcp": {                                   // optional
    "action_type": "mcp_tool_call",          // default
    "method": "MCP",                         // default
    "cost_per_call": 0.0,                    // set >0 to make budget apply
    "server_name": "safety-protocol-guard",  // announced to the client
    "gate_resources": true,                  // gate resources/read + subscribe (default true)
    "resource_read_action_type": "mcp_resource_read",         // default
    "resource_subscribe_action_type": "mcp_resource_subscribe", // default
    "allowed_uri_schemes": ["file"]          // default; reject other schemes
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
| `resources/read`, `resources/subscribe` | **Intercepted** when `mcp.gate_resources` is true (default). The URI is normalized, evaluated, and forwarded (rewritten to its normalized form) or denied. |
| `initialize` | Forwarded; `serverInfo` rewritten to identify the guard. |
| `tools/list`, `resources/list`, `resources/templates/list`, `prompts/*`, `completion/*`, `logging/*`, `ping` | Forwarded unchanged. |
| Notifications (`notifications/*`) | Forwarded unchanged. |
| Server-initiated requests (e.g. `sampling/createMessage`) | Forwarded; ids rewritten so they cannot collide with client ids. |
| Anything the guard cannot parse | Forwarded (the guard fails open on malformed JSON, closed on policy). |

## Resource reads and subscribes

Resource reads are a data-exfiltration path, so they are gated by default.
Each `resources/read` / `resources/subscribe` becomes one guard action:

| Field | Value |
| ----- | ----- |
| `action_type` | `mcp_resource_read` / `mcp_resource_subscribe` |
| `target` | the **normalized** resource URI |
| `method` | `MCP` |
| `params` | `{"uri": <normalized URI>}` |
| `cost` | `mcp.cost_per_call` |

The URI is normalized **before** the rule is consulted, so encoding and
traversal tricks cannot slip a URI past an allowlist:

- percent-decoded exactly once; a residual `%` (double-encoding, e.g.
  `%252e%252e`) is rejected;
- scheme and host lowercased, path case preserved (matching is
  case-insensitive);
- `.` dropped and `..` collapsed; a `..` that would escape the root is rejected;
- `file://localhost/…` and `file:///…` are treated as the same host;
- the scheme must be in `mcp.allowed_uri_schemes` (default `["file"]`).

A URI that fails normalization is **denied in every mode — including shadow**
and is never forwarded: it is malformed input, not a policy question. A URI
that normalizes but is out of scope behaves like a denied tool call (shadow mode
forwards it and records what policy would have done).

Setting `"gate_resources": false` forwards `resources/read` and
`resources/subscribe` **untouched**. That is deliberately loud: the scope linter
emits a non-blocking `MCP_RESOURCES_UNGATED` warning, and the audit chain records
a `resources_ungated` event. Use it only short-term, in shadow mode, while you
learn real traffic.

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
| GET | `/pending` | — | What is waiting for a human decision (requires the secret) |
| POST | `/approve` | `{token, approved?, approver?, reason?}` | Decide one (requires the secret) |
| GET | `/health` | — | `{ok, mode}` |

### Approver secret

The control endpoint is protected by an **approver secret**. At startup the
proxy generates one with `secrets.token_urlsafe(32)` and either writes it to a
file (`--approver-secret-file`, mode `0600`) or prints it to stderr once. Every
`POST /approve` and `GET /pending` must present it, either as
`X-Approver-Secret: <secret>` or `Authorization: Bearer <secret>`. A request
without it is rejected `401` and the attempt is written to the audit chain as
`approval_auth_failed` — so an agent that tries to approve its own action leaves
a record.

```bash
safety-guard mcp-proxy --config guard_config.json \
    --control-port 8788 --approver-secret-file /run/guard.secret -- <server>
SECRET=$(cat /run/guard.secret)
curl -s -H "X-Approver-Secret: $SECRET" localhost:8788/pending
curl -s -XPOST -H "X-Approver-Secret: $SECRET" localhost:8788/approve \
     -d '{"token":"<tok>","approver":"alice"}'
```

`--approver-secret` supplies a fixed secret instead of generating one.
`--no-approver-secret` disables the requirement, which is only allowed on
loopback and prints a warning. Binding the control endpoint to a **non-loopback
address without a secret is refused** at startup.

Tokens are hardened regardless of channel: they are **single-use**, **expire**
after `approval_ttl_s` (default 300s, configurable), are **bound to the exact
intent** (action_type + target + params — a retry with different params is not
auto-allowed), and the approver identity + channel are recorded in the audit
chain and in the shipped event. An agent cannot approve its own action
(`approver == agent_id` is refused), nor can an approval arrive on the same
`session_id` as the request.

Use `--no-control` to disable the endpoint, `--control-host`/`--control-port` to
move it. It binds `127.0.0.1` by default.

The approval must be decided by something the **agent cannot reach**. The secret
is a local step up, not a substitute for out-of-band approval: if you expose the
control endpoint to the agent's network (or the agent shares the operator's OS
user), approval becomes decorative (see
[threat model](../README.md#threat-model--non-goals)).

Approval channels today are the control endpoint and in-process calls. Stronger
out-of-band channels (signed one-time link over a messaging channel such as
Telegram, or a Unix-domain-socket/named-pipe control plane with peer-UID checks)
are roadmap; the token's properties above are what any channel must preserve.

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
- **`prompts/get` is not gated.** Prompts are an injection channel; today they
  pass through. Gating them is a roadmap item — do not treat them as vetted.
- **Tool *results* are not inspected.** A denied call never runs, but the
  content a successful tool returns flows to the agent unfiltered. Scanning
  results for prompt injection is out of scope here.
- **Resource URI normalization is lexical, not filesystem-aware.** It does not
  resolve symlinks or enforce a root on disk; the upstream server still has the
  final say on what a path means. It stops encoding and traversal tricks in the
  URI, not a symlink the server follows.
- **Only `resources/read` and `resources/subscribe` are gated.** `resources/list`
  passes through, so the agent can see resource URIs it cannot read.
