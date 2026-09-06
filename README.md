# AgentCover Sovereign: The Governance Engine

Giving an AI agent your bank or email access is a disaster waiting to happen. **AgentCover Sovereign** fixes that. We've built a sovereign governance engine that ensures your AI can only do exactly what you authorized—and not a penny or a byte more.

## 🛡️ Core Governance Layers

### 1. Deployment-Time Guardrails (The Linter)
Most safety systems are reactive; AgentCover is preventative. Before an agent is deployed, the system runs a static analysis of the `ScopeRules`. If a rule is too broad (e.g., using a prefix match on a root domain that could accidentally permit `/admin` or `/billing`), the linter flags it as a `Severity.ERROR`. 

**The system fails-closed:** An agent with an unsafe scope cannot be booted. This eliminates human error from the deployment pipeline.

### 2. Runtime Enforcement (The Guard)
Once active, every action is passed through the Safety Protocol:
*   **Binding:** Verifies the agent is still non-transferably bound to the accountable user.
*   **Closed Vocabulary:** Blocks any action type not explicitly registered (no "invented" verbs).
*   **Scope Validation:** Enforces exact/prefix/token matches and validates parameters against a JSON schema.
*   **Budget Caps:** Enforces both a global session limit and per-action cost caps.
*   **Approval Gates:** High-value or high-risk actions are paused for human sign-off.
*   **Kill Switch:** Immediate, global freeze of all agent activity.

### 3. Verifiable Accountability (The Audit)
Every event—allowed or blocked—is recorded in a hash-chained audit trail. This provides a tamper-resistant record of exactly what the agent attempted and why the guard allowed or blocked it, making the agent truly insurable.

## 🚀 Quick Start

### Installation
```bash
pip install .
```

### Basic Usage
```python
from safety_protocol import SafetyProtocol, ScopeRule

protocol = SafetyProtocol(
    agent_id="agent-001",
    user_id="alice",
    scope_rules=[
        ScopeRule(action_type="api_call", allowed_targets=["api.example.com"], match="prefix")
    ]
)
```

## 📝 Submission Details
Built for the **Nebius x NVIDIA Global AI Hackathon**. 
**Track:** Personal AI.
**Stack:** NVIDIA Nemotron, Nebius Token Factory, Python.
