# Your MCP agent just read `/etc/shadow` and nobody noticed

*A demo of `safety-protocol` 0.7.0: gating MCP resource reads and making
approvals something an agent can't self-serve.*

> Status: draft for publishing (blog / dev.to / LinkedIn). The transcript and
> audit chain below are real output from `examples/mcp_proxy_demo.py` against a
> fake MCP server, captured on 2026-10-16. The one placeholder is marked
> `[TODO]` at the end.

---

MCP gave agents a standard way to call tools. Two features quietly widened the
blast radius:

1. **Tools that mutate state** — `write_file`, `run_sql`, `send_email`.
2. **Resources** — `resources/read` hands the agent the contents of a file, a
   record, a database row. It is a first-class data-exfiltration path, and most
   "agent sandboxes" don't touch it.

Add a third: **approvals**. Plenty of frameworks let a tool be marked "needs a
human". But if the approval endpoint is reachable by the same process that made
the request, the agent can approve itself and the human-in-the-loop is
decoration.

`safety-protocol` is an enforcement layer that sits between the agent and the
world. Version 0.7.0 tightens the two edges above inside the MCP proxy:

- every `resources/read` / `resources/subscribe` is now evaluated, with the URI
  **normalized** (single percent-decode, traversal collapsed, scheme
  allowlisted) before any rule is consulted;
- approvals are **single-use, time-limited, bound to the exact intent, and
  attributed to a non-agent approver**, over a control endpoint that requires a
  secret.

No new dependency — the proxy speaks newline-delimited JSON-RPC, which *is* the
MCP stdio transport.

## The shape

```text
MCP client  <--stdio JSON-RPC-->  safety-guard mcp-proxy  <--stdio JSON-RPC-->  MCP server
   (Claude Desktop / agent host)                                   (filesystem, DB, …)
```

The guard is the only path to the tool server. A denied call never reaches
upstream — the agent gets a normal MCP error (`isError: true`) carrying the
reason.

## Run it

```bash
pip install safety-protocol==0.7.0

# what a tool + resource policy looks like
cat examples/mcp_guard_config.json

# put the guard in front of any MCP server
safety-guard mcp-proxy --config examples/mcp_guard_config.json -- \
    npx -y @modelcontextprotocol/server-filesystem /data
```

The policy in the demo:

- `read_file`, `list_directory` are allowed;
- `write_file` is allowed **only after a human approves it**;
- `resources/read` is allowed only under `file:///data/reports/*`;
- anything else is denied by default (scope is an allowlist, not a blocklist).

## The transcript

Real output from driving the proxy against a fake MCP server
(`examples/mcp_proxy_demo.py`). Trimmed to the interesting frames.

**An allowed tool call passes through:**

```text
[client -> guard]  tools/call read_file
  {"jsonrpc":"2.0","id":2,"method":"tools/call",
   "params":{"name":"read_file","arguments":{"path":"/data/notes.txt"}}}
[guard -> client]  ok: <contents of /data/notes.txt>
```

**A tool with no rule is denied — and never reaches the server:**

```text
[client -> guard]  tools/call delete_everything
  {"jsonrpc":"2.0","id":3,"method":"tools/call",
   "params":{"name":"delete_everything","arguments":{}}}
[guard -> client]  isError=true  (call blocked)
  text:   Blocked by safety guard: No scope rule permits action 'mcp_tool_call'
          on target 'delete_everything' — denied by default (scope is an
          allowlist, not a blocklist)
  guard:  {"kind":"denied","decision":"blocked_scope","rule_id":null,
           "request_id":"51a746f7","approval_token":null}
```

**A mutating tool is held, approved out of band, then retried:**

```text
[client -> guard]  tools/call write_file
  {"jsonrpc":"2.0","id":4,"method":"tools/call",
   "params":{"name":"write_file",
             "arguments":{"path":"/data/out.txt","content":"hello"}}}
[guard -> client]  isError=true  (call blocked)
  text:   Blocked by safety guard: this request requires human approval
          (token fcbdd9f58635). An operator must approve it, then the call can
          be retried.
  guard:  {"kind":"approval_required","decision":"pending_approval",
           "rule_id":"mcp-write","request_id":"c554c6cc",
           "approval_token":"fcbdd9f58635"}

[operator]        POST /approve  (approver secret from guard.secret)
[operator]        -> HTTP 200 {"ok":true,"approved":true}

[client -> guard]  tools/call write_file (retry)
[guard -> client]  ok: wrote 5 bytes to /data/out.txt
```

**Resource reads are gated by default — including traversal tricks:**

```text
[client -> guard]  resources/read q4.csv
  {"jsonrpc":"2.0","id":6,"method":"resources/read",
   "params":{"uri":"file:///data/reports/q4.csv"}}
[guard -> client]  ok: <contents of file:///data/reports/q4.csv>

[client -> guard]  resources/read (out of scope)
  {"jsonrpc":"2.0","id":7,"method":"resources/read",
   "params":{"uri":"file:///etc/shadow"}}
[guard -> client]  isError=true  (call blocked)
  text:   Blocked by safety guard: No scope rule permits action
          'mcp_resource_read' on target 'file:///etc/shadow' — denied by default
          (scope is an allowlist, not a blocklist)

[client -> guard]  resources/read (double-encoded traversal)
  {"jsonrpc":"2.0","id":8,"method":"resources/read",
   "params":{"uri":"file:///data/reports/%252e%252e/secret"}}
[guard -> client]  isError=true  (call blocked)
  text:   Blocked by safety guard: resource uri rejected: resource uri uses
          double-encoded characters ('%')
```

The last one is the point: `%252e%252e` is `%2e%2e` after one decode — a
double-encoded `..`. The URI is percent-decoded **exactly once**; a residual `%`
is rejected, so it is refused before any rule is consulted and **in every mode,
including shadow**. Malformed input is not a policy question, so it is never
forwarded.

## The audit chain

Every decision is written to a durable outbox as canonical JSON
(`events.jsonl`), each event hash-chained to the previous one — so the record is
tamper-evident and can be shipped to a receiver the operator does not control.
From the same run:

```jsonl
{"seq":1,"decision":"allowed","policy_decision":"allowed","action_type":"mcp_tool_call","target":"read_file","rule_id":"mcp-read","reason":null}
{"seq":2,"decision":"denied","policy_decision":"denied","action_type":"mcp_tool_call","target":"delete_everything","rule_id":null,"reason":"No scope rule permits action 'mcp_tool_call' on target 'delete_everything' — denied by default (scope is an allowlist, not a blocklist)"}
{"seq":3,"decision":"needs_approval","policy_decision":"needs_approval","action_type":"mcp_tool_call","target":"write_file","rule_id":"mcp-write","reason":null}
{"seq":4,"decision":"approved","policy_decision":"approved","action_type":"mcp_tool_call","target":"write_file","rule_id":"mcp-write","reason":null}
{"seq":5,"decision":"allowed","policy_decision":"allowed","action_type":"mcp_tool_call","target":"write_file","rule_id":"mcp-write","reason":null}
{"seq":6,"decision":"allowed","policy_decision":"allowed","action_type":"mcp_resource_read","target":"file:///data/reports/q4.csv","rule_id":"mcp-read-reports","reason":null}
{"seq":7,"decision":"denied","policy_decision":"denied","action_type":"mcp_resource_read","target":"file:///etc/shadow","rule_id":null,"reason":"No scope rule permits action 'mcp_resource_read' on target 'file:///etc/shadow' — denied by default (scope is an allowlist, not a blocklist)"}
{"seq":8,"decision":"denied","policy_decision":"denied","action_type":"mcp_resource_read","target":"file:///data/reports/%252e%252e/secret","rule_id":null,"reason":"resource uri rejected: resource uri uses double-encoded characters ('%')"}
```

You can read the whole story off the chain: allowed → denied → held → approved →
retried → allowed, then the resource reads. Eight decisions, eight hashes.

## Why the approval part matters

An approval is only worth something if the agent can't reach the approver. In
0.7.0:

- the control endpoint generates an **approver secret** at startup
  (`secrets.token_urlsafe(32)`), written to a `0600` file or printed once;
  `POST /approve` and `GET /pending` require it. A call without it is `401`, and
  the attempt is written to the audit chain as `approval_auth_failed` — so an
  agent that *tries* to approve its own action leaves a record.
- binding the control endpoint to a **non-loopback** address without a secret is
  **refused at startup**.
- tokens are **single-use** and **expire** (`approval_ttl_s`, default 300s).
- an approval is **bound to the exact intent** (action_type + target + params);
  a retry with different params is not auto-allowed.
- the **approver cannot be the agent** (`approver == agent_id` is refused), nor
  can an approval arrive on the same `session_id` as the request.
- the approver identity and channel land in both the audit chain and the shipped
  event.

None of this is a substitute for real out-of-band approval. The secret is a
local step-up. If you expose the control endpoint to the agent's network, or the
agent shares the operator's OS user, approval becomes decorative again. The
token properties above are what *any* approval channel has to preserve.

## What it does not do

Being honest about the edges:

- **stdio only.** A streamable-HTTP MCP server needs an HTTP relay in front of
  it (roadmap).
- **Tool results are not inspected.** A denied call never runs, but the content
  a successful tool returns flows to the agent unfiltered.
- **`prompts/get` is not gated.** Prompts are an injection channel; today they
  pass through.
- **Resource URI normalization is lexical, not filesystem-aware.** It stops
  encoding and traversal tricks in the URI, not a symlink the server follows.
- **Only `resources/read` and `resources/subscribe` are gated.** `resources/list`
  passes through, so the agent can see URIs it cannot read.
- **`tools/list` is not filtered.** The agent can see tools it may not call;
  calling them is denied.

## Try it

```bash
pip install safety-protocol==0.7.0

git clone https://github.com/TheDub-lab/agentcover-sovereign
cd agentcover-sovereign
python examples/mcp_proxy_demo.py       # the run above, end to end
```

MIT-licensed SDK. The audit/evidence service (receiver, signed receipts) is a
separate layer.

---

## [TODO] Real agent transcript

Replace this section with a transcript from a real MCP host — e.g. Claude
Desktop pointed at `safety-guard mcp-proxy`, or a Strands agent using the
`guard_strands_tool` wrapper — showing:

- the agent attempting a tool it shouldn't call, and the human-readable error it
  receives;
- the operator approving a held call and the agent completing it on retry;
- a resource read attempt outside scope.

Screenshot or pasted log is fine. Keep it unedited — the point is that the guard
fires in a real host, not just the harness.
