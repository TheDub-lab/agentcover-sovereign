# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Michael / TheDub-lab
"""
Safety Protocol Framework for LLM Agents

A framework for building safe, accountable AI agents that operate
through enforced safety protocols rather than relying on the model's
good behavior.

The core principle: the user is accountable for their agents. Every
agent action passes through a safety protocol that enforces binding,
scope, budget, approval gates, monitoring, audit trail, and kill switch.

The agent operates freely WITHIN these bounds. The bounds are enforced
by infrastructure, not by hoping the agent behaves.

When the agent messes up, the audit trail tells you what happened, the
binding tells you who's accountable, and the next iteration has tighter
scope.

This framework implements a reference architecture for safe agents:

Layer 1: Safety Protocol (enforcement) — scope, budget, approval, monitoring,
    audit trail (off-chain complete record), kill switch.

Layer 2: On-chain anchors — SBT-style non-transferable binding, on-chain audit
    for key events (high-value actions, approvals, kill switch, scope violations).
    Verifiable by anyone. Tamper-resistant.

Layer 3: Insurance interface — claims-ready evidence, underwriter reports,
    control-adjusted exposure estimates. The protocol makes the agent insurable
    by providing verifiable evidence of what happened and controls that operated.

The framework is framework-agnostic: works with any LLM, any runtime, any chain.
In production, swap the simulated on-chain layer for real ERC-5192/ERC-8004 + a
real chain, and the insurance interface for a real insurer's claims process.

Installation:
    pip install safety-protocol

Quick start:

    from safety_protocol import (
        SafetyProtocol, BoundAgent, ScopeRule, AuditTrail, Monitor
    )

    audit = AuditTrail()
    protocol = SafetyProtocol(
        agent_id="agent-001",
        user_id="alice",
        scope_rules=[
            ScopeRule(
                action_type="api_call",
                allowed_targets=["https://api.example.com/v1/*"],
                forbidden_targets=["admin", "billing"],
                max_cost=5.0,
            ),
        ],
        budget_limit=50.0,
        approval_threshold_cost=10.0,
        audit=audit,
    )

    agent = BoundAgent(
        agent_id="agent-001",
        user_id="alice",
        safety_protocol=protocol,
    )

    result = agent.propose_action(
        action_type="api_call",
        target="https://api.example.com/v1/search",
        params={"query": "test"},
        estimated_cost=2.50,
    )

    print(result.outcome)  # ActionOutcome.ALLOWED

For the full reference architecture with on-chain binding, on-chain audit,
and insurance interface:

    from safety_protocol.deployment import ReferenceDeployment

    deployment = ReferenceDeployment(
        agent_id="agent-001",
        user_id="alice",
        agent_name="ResearchAgent",
        agent_role="AI research assistant",
    )

    # Agent proposes action — full stack enforces
    result = deployment.agent_propose_action(
        action_type="api_call",
        target="https://api.example.com/v1/search",
        params={"query": "test"},
        estimated_cost=2.50,
    )

    # Get binding proof (verifiable by anyone)
    proof = deployment.get_binding_proof()

    # Get claims evidence (for insurance)
    evidence = deployment.get_claim_evidence(
        claim_description="Agent made incorrect API call",
    )

    # Get underwriter package (for binding coverage)
    underwriter = deployment.get_underwriter_package(
        agent_description="Research agent that calls APIs",
        task_profile="API calls, message sending",
        max_potential_loss=5000.0,
    )

The problem this solves:
-----------------------
AI agents can take actions with real consequences: spending money, calling
APIs, modifying systems, sending messages, spawning subagents. The model's
good behavior is not reliable enough to depend on. The safety protocol makes
the agent *safe to operate* by enforcing constraints in infrastructure, not
in prompts.

When the agent messes up, you need to know: what happened, who's accountable,
what controls operated, what can be reconstructed. The binding + audit trail
+ on-chain record answer these questions. The insurance interface makes the
agent insurable by providing claims-ready evidence.

The enforcement library (Layer 1) is production-usable in the sense that it is
feature-complete for its scope and its behavior is covered by the test suite
(run on Python 3.10-3.12 in CI). It has NOT been independently security-audited
and has not been deployed against real money or credentials by the authors.
Treat it as reviewed-by-test, not as audited infrastructure. The on-chain layer
is simulated (same interface as a real chain). In production, use ERC-5192 SBT
or ERC-8004 on a real chain, and connect the insurance interface to a real
insurer's claims process.

The architecture is composable: use the protocol alone, add on-chain binding,
add on-chain audit, add insurance interface — each layer is independent and
adds value on its own.

Documentation:
    - Core protocol: src/safety_protocol/protocol.py
    - On-chain binding: src/safety_protocol/onchain.py
    - On-chain audit: src/safety_protocol/onchain_audit.py
    - Insurance interface: src/safety_protocol/insurance.py
    - Reference deployment: src/safety_protocol/deployment.py
    - Example (LLM agent): examples/llm_agent.py
    - Example (reference deployment): examples/reference_deployment.py
"""
from .config import build_protocol_from_config
from .core import (
    ActionOutcome,
    ActionRequest,
    ActionResult,
    ApprovalRecord,
    AuditTrail,
    Monitor,
    ProtocolState,
    ScopeRule,
)
from .integrations import (
    ToolDecision,
    evaluate_tool_call,
    guard_langchain_tool,
    guard_langchain_tools,
    guard_strands_tool,
    guard_strands_tools,
)
from .mcp_proxy import MCPProxy
from .onchain_payment_verifier import OnChainPaymentVerifier
from .payments import PaymentEnvelope, SafeSpendAgent, SimWallet
from .protocol import BoundAgent, SafetyProtocol
from .real_wallet import HAS_REAL_CRYPTO, RealWallet
from .scope_linter import Finding, Severity, lint_report, lint_rules
from .shipping import (
    LogShipper,
    Outbox,
    config_hash,
    hash_event,
    params_digest,
    shipper_from_config,
    verify_event_hash,
)

# BSL platform layer: the hosted service + on-chain audit / insurance evidence
# stack. Shipped separately from the MIT wheel, so it is optional at import
# time — the MIT SDK works on its own.
try:
    from .platform.deployment import ReferenceDeployment
    from .platform.guard_service import GuardService
    from .platform.insurance import InsuranceInterface
    from .platform.onchain import OnChainBindingRegistry, OnChainBoundProtocol
    from .platform.onchain_audit import DualAudit, OnChainAudit
except ImportError:  # pragma: no cover - MIT-only installs
    ReferenceDeployment = None  # type: ignore
    GuardService = None  # type: ignore
    InsuranceInterface = None  # type: ignore
    OnChainBindingRegistry = None  # type: ignore
    OnChainBoundProtocol = None  # type: ignore
    DualAudit = None  # type: ignore
    OnChainAudit = None  # type: ignore

try:
    from importlib.metadata import PackageNotFoundError
    from importlib.metadata import version as _version

    __version__ = _version("safety-protocol")
except PackageNotFoundError:  # running from a source checkout
    __version__ = "0.6.0"
__all__ = [
    "ActionOutcome",
    "ProtocolState",
    "ActionRequest",
    "ActionResult",
    "ApprovalRecord",
    "ScopeRule",
    "AuditTrail",
    "Monitor",
    "SafetyProtocol",
    "BoundAgent",
    "MCPProxy",
    "ToolDecision",
    "evaluate_tool_call",
    "guard_strands_tool",
    "guard_strands_tools",
    "guard_langchain_tool",
    "guard_langchain_tools",
    "OnChainBindingRegistry",
    "OnChainBoundProtocol",
    "OnChainAudit",
    "DualAudit",
    "InsuranceInterface",
    "ReferenceDeployment",
    "SafeSpendAgent",
    "SimWallet",
    "PaymentEnvelope",
    "RealWallet",
    "HAS_REAL_CRYPTO",
    "OnChainPaymentVerifier",
    "LogShipper",
    "Outbox",
    "shipper_from_config",
    "config_hash",
    "hash_event",
    "verify_event_hash",
    "params_digest",
    "lint_rules",
    "lint_report",
    "Finding",
    "Severity",
    "GuardService",
    "build_protocol_from_config",
    "__version__",
]
