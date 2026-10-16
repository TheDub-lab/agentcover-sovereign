# safety-protocol

[![CI](https://github.com/TheDub-lab/agentcover-sovereign/actions/workflows/ci.yml/badge.svg)](https://github.com/TheDub-lab/agentcover-sovereign/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/safety-protocol.svg)](https://pypi.org/project/safety-protocol/)
[![Python](https://img.shields.io/pypi/pyversions/safety-protocol.svg)](https://pypi.org/project/safety-protocol/)
[![License: MIT](https://img.shields.io/badge/SDK%20license-MIT-yellow.svg)](LICENSE)
[![License: BSL 1.1](https://img.shields.io/badge/platform%20license-BSL%201.1-blue.svg)](LICENSE-BSL)

Enforceable governance for LLM agents. Instead of hoping the model behaves,
every action passes through infrastructure that enforces **binding, closed
vocabulary, least-privilege scope, spend caps, approval gates, a hash-chained
audit trail, and a kill switch**. Deny-by-default: an action is permitted only
if a rule explicitly allows it.

The agent proposes; the protocol decides. The check is not a prompt instruction,
so the model cannot reason its way around **the gate** — provided the gate is
actually on the only path to the action. That assumption and its limits are
spelled out in [Threat model & non-goals](#threat-model--non-goals); read it
before trusting the guard with a capability.

## Install

```bash
pip install safety-protocol
```

Zero runtime dependencies — the guard, scope linter, audit trail and reference
deployment are stdlib. Optional integrations are extras:

| Extra     | Adds                                                        |
| --------- | ----------------------------------------------------------- |
| `onchain` | `requests` — verify a settled payment against a JSON-RPC node |
| `crypto`  | `eth-account` — real EIP-3009 / USDC settlement signing      |
| `demo`    | `openai` — the repo-root Nebius/Nemotron demo agent          |

```bash
pip install "safety-protocol[onchain,crypto]"
```

## Quickstart (library)

```python
from safety_protocol import SafetyProtocol, BoundAgent, ScopeRule

protocol = SafetyProtocol(
    agent_id="agent-001",
    user_id="alice",
    scope_rules=[
        ScopeRule(
            action_type="api_call",
            allowed_targets=["https://api.example.com/v1/search"],
            match="exact",
            methods=["POST"],
            param_schema={
                "required": ["query"],
                "properties": {"query": {"type": "string", "maximum": 200}},
                "additional_properties": False,
            },
            forbidden_targets=["admin", "billing"],
            max_cost=1.00,
        ),
    ],
    budget_limit=50.0,
    approval_threshold_cost=10.0,
    allowed_action_types=["api_call"],
)

agent = BoundAgent(agent_id="agent-001", user_id="alice", safety_protocol=protocol)

result = agent.propose_action(
    action_type="api_call",
    target="https://api.example.com/v1/search",
    params={"query": "test"},
    estimated_cost=2.50,
)
print(result.outcome)  # ActionOutcome.ALLOWED
```

## The guard (CLI + HTTP)

Give the guard a **user-controlled** config; it lints the rules before going
live and **fails closed** — a config that is too broad refuses to start. The
agent only ever sends intents; it can never widen its own scope.

```bash
safety-guard init  --out guard_config.json          # write a default config
safety-guard lint  --config guard_config.json       # exit 1 if too broad
safety-guard check --config guard_config.json \
    --action api_call --target https://api.research.example/v1/search \
    --method POST --params '{"query":"hi"}'
safety-guard pay   --config guard_config.json \
    --recipient 0xMerchant1111111111111111111111111111111 --usd 0.10
safety-guard serve --config guard_config.json       # HTTP on 127.0.0.1:8080
```

The HTTP surface (any agent, any language):

| Method | Path           | Body                                            |
| ------ | -------------- | ----------------------------------------------- |
| POST   | `/guard`       | `{action_type, target, method?, params?, cost?}` |
| POST   | `/pay`         | `{recipient, usd, resource?}`                    |
| POST   | `/approve`     | `{token, approved, approver}`                    |
| POST   | `/killswitch`  | `{reason}`                                       |
| GET    | `/audit`       | — (immutable decision log)                       |
| GET    | `/health`      | — (status + lint summary)                        |

Equivalent module entry point: `python -m safety_protocol.guard_service --config guard_config.json`.

## Config reference

```jsonc
{
  "agent_id": "guard-agent",
  "user_id": "alice",
  "budget_limit": 20.0,              // global session cap (null = none)
  "approval_threshold_cost": 2.0,    // actions >= this need human sign-off
  "allowed_action_types": ["api_call", "payment"],   // closed verb vocabulary
  "scope_rules": [
    {
      "action_type": "api_call",
      "allowed_targets": ["https://api.research.example/v1/search"], // allowlist
      "match": "exact",              // exact | prefix | glob | regex
      "methods": ["POST"],           // transport verbs permitted
      "param_schema": {              // params MUST satisfy this
        "required": ["query"],
        "properties": {"query": {"type": "string", "maximum": 200}},
        "additional_properties": false
      },
      "forbidden_targets": ["admin", "billing"],
      "forbid_match": "token",       // token | substring
      "max_cost": 1.00,              // per-rule cap (tightest wins)
      "requires_approval": false
    }
  ]
}
```

Every dimension is enforced. Leaving any of them broad (a wildcard prefix, an
unbound method, an unvalidated param) is what makes the other controls
decorative — the `safety-guard lint` command exists to catch exactly that
before deploy.

## MCP proxy — route every tool call through the guard

The five-minute integration. Put the guard between an MCP client (Claude
Desktop, an agent host, another agent) and a real MCP server, and every tool
call the agent makes is evaluated before it reaches the server.

```bash
safety-guard mcp-proxy --config guard_config.json -- \
    npx -y @modelcontextprotocol/server-filesystem /data
```

The proxy speaks the MCP stdio transport (newline-delimited JSON-RPC) and has no
extra dependencies. An MCP scope rule binds the **tool name** and its
**arguments**:

```jsonc
{
  "id": "mcp-read",
  "action_type": "mcp_tool_call",
  "allowed_targets": ["read_file", "list_directory"],   // tool names
  "match": "exact",
  "methods": ["MCP"],                                   // transport verb
  "param_schema": {                                     // the tool's arguments
    "required": ["path"],
    "properties": {"path": {"type": "string"}},
    "additional_properties": false
  },
  "requires_approval": false
}
```

- `tools/call` is intercepted, and so are `resources/read` and
  `resources/subscribe` (on by default, `mcp.gate_resources`). The resource URI
  is normalized — single percent-decode, `..` collapsed with traversal
  rejected, scheme allowlisted — *before* the rule is consulted, so `%2e%2e/`
  cannot slip past a `file:///data/reports/*` rule. `initialize`, `tools/list`,
  resources list, prompts and notifications pass through untouched; the
  `initialize` reply is annotated so the client can see the guard is in the path.
- A blocked call returns a normal MCP error (`isError: true`) carrying the
  reason and the matched rule, so the agent can react instead of silently
  failing. A denied call never reaches the upstream server.
- Tools that require approval are held; the agent gets the approval token, an
  operator decides over the localhost control endpoint (`GET /pending`,
  `POST /approve`), then the agent retries. The control endpoint requires an
  approver secret (generated at start); tokens are single-use, expire, and are
  bound to the exact intent, and the approver identity + channel land in the
  audit chain. A non-loopback control host without a secret is refused.
- `shadow` mode forwards everything but records what policy *would* have denied.
- `mcp.cost_per_call` (default `0`) gives every call a declared cost, so the
  budget and approval threshold apply to tool calls too.

Full detail: [`docs/mcp-proxy.md`](docs/mcp-proxy.md). If your agent is
in-process instead (Strands, LangChain), guard the tools directly — see below.

## Strands & LangChain wrappers — gate tool calls in-process

When the agent calls tools in-process (no MCP server), wrap each tool so the
guard runs *inside* the tool call, before the tool body. A denied call never
executes; the agent receives a normal tool error carrying the guard's reason.

```python
from safety_protocol.integrations import (
    guard_strands_tool, guard_langchain_tool,
)

# Strands
from strands import Agent, tool

@tool
def read_file(path: str) -> str:
    """Read a file."""
    return open(path).read()

agent = Agent(tools=[guard_strands_tool(read_file, protocol)])

# LangChain (langchain-core)
from langchain_core.tools import tool as lc_tool

@lc_tool
def delete_all(path: str) -> str:
    """Delete everything."""
    return do_delete(path)

safe_delete = guard_langchain_tool(delete_all, protocol)  # raise_on_deny=True to raise
```

The wrapper keeps the tool's name, description and input schema, so the model
sees no change; only the execution path is gated. Each call becomes one guard
action (`action_type="tool_call"`, `target`=tool name, `params`=arguments), so
scope rules, budget, approval and the kill switch all apply exactly as they do
to any other action.

```jsonc
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
  }
}
```

Full detail: [`docs/integrations.md`](docs/integrations.md). Both SDKs are
optional — the wrappers import them lazily, so the core SDK stays
dependency-free.

## Log shipping (third-party evidence)

A guard can ship each decision to a receiver the operator does not control, so
the local hash chain becomes evidence someone else holds. The **sender**
(`safety_protocol.shipping`) is in the free MIT SDK; the **receiver**
(`safety_protocol.platform.receiver`, BSL) verifies the chain and returns a
signed receipt.

```jsonc
"mode": "enforce",                 // or "shadow": log what policy would block, allow anyway
"shipping": {
  "receiver_url": "https://logs.example.com",
  "api_key": "per-agent key",
  "batch_size": 50, "flush_interval_s": 5, "heartbeat_interval_s": 60,
  "log_params": "none"             // none | redacted | full (raw params ship only if not none)
}
```

Shipping is asynchronous and durable (local outbox first, batches, retry with
backoff); actions never wait on the receiver. Raw params are never shipped by
default — only `params_digest` and `param_keys`. See
[`docs/log-shipping.md`](docs/log-shipping.md) for the full spec.

## Threat model & non-goals

### The assumption this rests on

Enforcement holds only if the guard is a **chokepoint**. "The agent cannot talk
its way around it" is true when one of these is true — otherwise the claim is
just what the guard says about traffic it happens to see:

1. **The guard holds the capability.** The wallet key, the API credential, the
   SMTP login lives with the guard; the agent asks the guard to use it. The
   agent has nothing to use directly.
2. **The guard is the only egress path.** All of the agent's network and tool
   access goes through the guard (proxy / firewall), and the agent has no other
   route to the network, the filesystem, or a second credential.

The MCP proxy and the Strands/LangChain wrappers are both shape (2) for tool
calling: the agent's only path to a tool is through the guard (in-process, the
wrapped tool object is the only handle; over MCP, the proxy is the only path to
the server).

If the agent keeps its own credentials or has egress the guard does not see,
every control here is **advisory**. The guard will faithfully evaluate, deny and
record what is put in front of it; the agent acts around it anyway. This is the
most likely real-world failure, and it is a deployment problem, not a library
bug.

### What it does defend against

- A model induced (prompt injection, jailbreak, "ignore previous instructions")
  to attempt an action outside the declared scope — blocked and recorded,
  because the bound is in infrastructure rather than in a prompt.
- Spend beyond a cap, an action above the approval threshold, a revoked binding
  or an engaged kill switch — regardless of what the model believes.
- After-the-fact tampering with the local audit record (hash chain), and — with
  log shipping — with the record as held by a third party.

### What it does not defend against

- **A compromised host.** Code running on the host can read the guard's memory,
  edit the config, kill the process, or use the credentials itself. Host and OS
  hardening are out of scope.
- **Misconfiguration.** `safety-guard lint` catches the mechanically broad
  patterns it knows (catch-all prefixes, unbound methods, missing param
  schemas). It cannot know your intent. `https://*`, an over-permissive
  `param_schema`, or a `regex` written too loosely is enforced exactly as
  written. Correct policy is the operator's job.
- **Bypass paths.** Any credential or egress the guard does not hold (see the
  assumption above).
- **Semantic mistakes.** The guard compares the action you *declared* against
  the policy you *wrote*. A confused model taking a wrong-but-in-scope action is
  not caught — it is not an intent classifier.
- **A dishonest recorder.** The chain proves integrity of the record, not
  honesty of the recorder. A guard on an owned host can emit a well-formed,
  consistent chain, and a receiver receipt attests only that those bytes arrived
  at that time. Non-repudiation needs a signing key held somewhere the guard
  cannot reach — not implemented.
- **Availability and side channels.** It is not a sandbox or an IDS, does not
  detect exfiltration through an allowed channel, and does not measure real
  cost: cost is declared by the caller and used for the caps.
- **Approval integrity.** Tokens are single-use, expire, are bound to the exact
  intent, and refuse self-approval — so a leaked token cannot be replayed and an
  agent cannot approve itself. But approval is only as strong as the channel: the
  control endpoint's secret is a local step up, and if the agent shares the
  operator's OS user or can reach the control endpoint, approval is decorative.
  Out-of-band approval over a channel the agent cannot touch
  (signed one-time link / separate UDS with peer-UID checks) is roadmap; the
  approver must be a separate, human-controlled channel.
- **The on-chain and insurance layers.** The on-chain layer is simulated, the
  insurance layer is a reference interface. Neither is production
  infrastructure yet.

## Architecture

| Layer | What it is | Status |
| ----- | ---------- | ------ |
| **1. Enforcement** | binding, scope, budget, approval, monitor, audit, killswitch | production-usable (see basis below) |
| **2. On-chain anchors** | SBT-style binding + on-chain audit of key events | **simulated** (in-memory, same interface as a real chain) |
| **3. Insurance** | claims evidence, underwriter reports | interface / reference |

**Basis for "production-usable" (Layer 1).** Feature-complete for its stated
scope, with the behavior covered by the test suite, run on Python 3.10–3.12 in
CI on every push. That is what the claim rests on: **tests, not a review or a
deployment.** There has been no independent security audit and no production
deployment by the authors against real money or real credentials. Treat it as
reviewed-by-test rather than audited infrastructure, and read
[Threat model & non-goals](#threat-model--non-goals) before it holds a
capability you care about.

> **The on-chain layer is simulated.** It is not third-party verifiable until a
> real contract is deployed. The library discloses this in every binding proof
> (`on_chain_backend: "simulated_in_memory"`). Use ERC-5192 SBT or ERC-8004 on a
> real chain in production.

`ReferenceDeployment` wires all three layers together; the layers are
composable and each adds value on its own.

## Adoption

Current numbers, stated honestly rather than dressed up (as of 2026-10-15):

- **PyPI downloads:** ~300 since first publication (source: pypistats.org).
- **GitHub:** 0 stars, 0 forks. It is early.
- **Used by**:
  - `paypal-agentsafe` (Nebius x NVIDIA Global AI Hackathon) — its governance
    layer imports `safety_protocol.scope_linter` and wraps `SafetyProtocol`.
  - The AgentCover CALL-E phone-agent demo in `awesome-phone-call-agents` —
    vendors a faithful subset of this guard as its enforcement engine.
  - The demo agents in this repo, including the Hermes-venv insurance
    simulation (`run_mc.bat`, `run_tamagotchi.bat`) and the settlement demos.

A feature list says what it can do; the list above is what it actually runs in
front of. If you put it in front of something, open an issue — we would rather
have three real users listed than a bigger number.

## Development

```bash
pip install -e ".[dev]"
python -m pytest
ruff check
```

The repo-root files (`sovereign_agent.py`, `agent_capabilities.py`) are a
standalone demo agent and are **not** part of the package:

```bash
pip install -e ".[demo]"
python sovereign_agent.py --offline     # no API key needed; same gate logic
python sovereign_agent.py               # live via NEBIUS_API_KEY
```

## Origin

Originally built for the Nebius x NVIDIA Global AI Hackathon (Track: Personal
AI), then hardened into a general enforcement library.

## License

Open core. The enforcement SDK is **MIT** (see [`LICENSE`](LICENSE)); the
hostable service + on-chain audit/evidence platform layer
(`src/safety_protocol/platform/`) is **Business Source License 1.1**
(see [`LICENSE-BSL`](LICENSE-BSL)). The PyPI wheel ships the MIT SDK only.
Full details in [`LICENSING.md`](LICENSING.md).
