# safety-protocol

[![CI](https://github.com/TheDub-lab/agentcover-sovereign/actions/workflows/ci.yml/badge.svg)](https://github.com/TheDub-lab/agentcover-sovereign/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/safety-protocol.svg)](https://pypi.org/project/safety-protocol/)
[![Python](https://img.shields.io/pypi/pyversions/safety-protocol.svg)](https://pypi.org/project/safety-protocol/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Enforceable governance for LLM agents. Instead of hoping the model behaves,
every action passes through infrastructure that enforces **binding, closed
vocabulary, least-privilege scope, spend caps, approval gates, a hash-chained
audit trail, and a kill switch**. Deny-by-default: an action is permitted only
if a rule explicitly allows it.

The agent proposes; the protocol decides. The agent cannot talk its way around
it, because the check is not a prompt instruction.

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

## Architecture

| Layer | What it is | Status |
| ----- | ---------- | ------ |
| **1. Enforcement** | binding, scope, budget, approval, monitor, audit, killswitch | production-usable |
| **2. On-chain anchors** | SBT-style binding + on-chain audit of key events | **simulated** (in-memory, same interface as a real chain) |
| **3. Insurance** | claims evidence, underwriter reports | interface / reference |

> **The on-chain layer is simulated.** It is not third-party verifiable until a
> real contract is deployed. The library discloses this in every binding proof
> (`on_chain_backend: "simulated_in_memory"`). Use ERC-5192 SBT or ERC-8004 on a
> real chain in production.

`ReferenceDeployment` wires all three layers together; the layers are
composable and each adds value on its own.

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

MIT. See [`LICENSE`](LICENSE).
