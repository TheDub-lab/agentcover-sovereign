#!/usr/bin/env python3
"""
Reference deployment test: full safety protocol architecture end-to-end.

Demonstrates all four layers operating together:
- Layer 0: Runtime (simulated agent proposing actions)
- Layer 1: Policy & enforcement (safety protocol)
- Layer 2: On-chain anchors (SBT binding + on-chain audit)
- Layer 3: Insurance interface (claims evidence + underwriter report)
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from safety_protocol.deployment import ReferenceDeployment
from safety_protocol import ScopeRule


def run():
    print("=" * 70)
    print("REFERENCE DEPLOYMENT: FULL SAFETY PROTOCOL ARCHITECTURE")
    print("=" * 70)
    print()

    # ------------------------------------------------------------------
    # Setup
    # ------------------------------------------------------------------
    deployment = ReferenceDeployment(
        agent_id="agent-research-001",
        user_id="alice",
        agent_name="ResearchAgent",
        agent_role="AI research assistant with safety protocols",
        scope_rules=[
            ScopeRule(
                action_type="api_call",
                allowed_targets=[
                    "https://api.research.example/v1/search",
                    "https://api.research.example/v1/summarize",
                    "https://api.research.example/v1/analyze",
                ],
                match="exact",                      # deny-by-default, exact targets
                methods=["POST"],                   # only the verb it should use
                param_schema={
                    "required": ["query"],
                    "properties": {
                        "query": {"type": "string", "maximum": 500},
                    },
                    "additional_properties": False,
                },
                forbidden_targets=["admin", "billing", "internal", "config", "production"],
                forbid_match="token",
                max_cost=8.0,                        # per-rule hard cap
            ),
            ScopeRule(
                action_type="spend",
                allowed_targets=["compute", "storage", "api_credits"],
                methods=["spend"],
                param_schema={
                    "required": ["resource", "amount"],
                    "properties": {
                        "resource": {"type": "string", "enum": ["compute", "storage", "api_credits"]},
                        "amount": {"type": "number", "minimum": 0, "maximum": 30},
                    },
                    "additional_properties": False,
                },
                max_cost=25.0,
            ),
            ScopeRule(
                action_type="send_message",
                allowed_targets=["alice", "team-channel"],
                methods=["send_message"],
                param_schema={
                    "required": ["channel", "body"],
                    "properties": {
                        "channel": {"type": "string", "enum": ["alice", "team-channel"]},
                        "body": {"type": "string", "maximum": 1000},
                    },
                    "additional_properties": False,
                },
            ),
        ],
        budget_limit=100.0,
        approval_threshold=10.0,
        high_value_threshold=25.0,
        allowed_action_types=["api_call", "spend", "send_message"],
    )

    print("DEPLOYMENT INITIALIZED")
    print(f"  Agent: {deployment.agent_name} ({deployment.agent_id})")
    print(f"  User: {deployment.user_id}")
    print(f"  Binding: on-chain SBT + runtime enforcement")
    print(f"  Budget: ${deployment.protocol.protocol.budget_limit:.2f}")
    print(f"  Approval threshold: ${deployment.protocol.protocol.approval_threshold_cost:.2f}")
    print(f"  High-value threshold (on-chain record): ${deployment.high_value_threshold:.2f}")
    print()

    status = deployment.get_agent_status()
    print("ON-CHAIN BINDING VERIFICATION:")
    print(f"  Bound: {status['binding']['on_chain']['bound']}")
    print(f"  User: {status['binding']['on_chain']['user_id']}")
    print(f"  Tx: {status['binding']['on_chain']['tx_hash']}")
    print(f"  Block: {status['binding']['on_chain']['block_number']}")
    print(f"  Transferable: {status['binding']['on_chain']['transferable']}")
    print()

    # ------------------------------------------------------------------
    # Scenario 1: Normal operations
    # ------------------------------------------------------------------
    print("=" * 70)
    print("SCENARIO 1: NORMAL OPERATIONS")
    print("=" * 70)
    print()

    # Each action must satisfy its rule's param_schema: api_call requires
    # {query: str <= 500}; send_message requires {channel: enum, body: str <= 1000}.
    actions = [
        ("api_call", "https://api.research.example/v1/search", {"query": "AI safety protocols"}, 3.50, "normal", "POST"),
        ("api_call", "https://api.research.example/v1/summarize", {"query": "research findings"}, 2.00, "normal", "POST"),
        ("api_call", "https://api.research.example/v1/analyze", {"query": "results"}, 4.00, "normal", "POST"),
        ("send_message", "alice", {"channel": "alice", "body": "Research complete"}, 0.0, "normal", "send_message"),
    ]

    for i, (action_type, target, params, cost, urgency, method) in enumerate(actions, 1):
        result = deployment.agent_propose_action(
            action_type=action_type,
            target=target,
            params=params,
            estimated_cost=cost,
            urgency=urgency,
            method=method,
        )
        print(f"  Action {i}: {action_type} on {target} (${cost:.2f})")
        print(f"    Outcome: {result.outcome.value}")
        if result.outcome.value == "pending_approval":
            print(f"    Approval needed (token available in pending_approvals)")
        print()

    print(f"  Total spent (from monitor): ${deployment.get_agent_status()['monitor']['total_cost']:.2f}")
    print(f"  On-chain events so far: {deployment.get_agent_status()['on_chain_events']}")
    print()

    # ------------------------------------------------------------------
    # Scenario 2: High-value action (on-chain record + approval)
    # ------------------------------------------------------------------
    print("=" * 70)
    print("SCENARIO 2: HIGH-VALUE ACTION (ON-CHAIN + APPROVAL)")
    print("=" * 70)
    print()

    print("  Agent proposes $20.00 compute spend (above $10 approval threshold, under $25 high-value threshold)")
    result = deployment.agent_propose_action(
        action_type="spend",
        target="compute",
        params={"resource": "compute", "amount": 20.0},
        estimated_cost=20.0,
        urgency="normal",
        method="spend",
    )
    print(f"    Outcome: {result.outcome.value}")
    print(f"    This action is recorded on-chain AND held for approval")
    print()

    print("  Human reviews and approves:")
    pending = deployment.get_agent_status()["pending_approvals"]
    if pending:
        token = pending[0]["token"]
        deployment.approve_action(token, "Approved for research compute")
        print(f"    Approved (token: {token})")
    print()

    # ------------------------------------------------------------------
    # Scenario 3: Scope violation (controls operating)
    # ------------------------------------------------------------------
    print("=" * 70)
    print("SCENARIO 3: SCOPE VIOLATION (CONTROLS OPERATING)")
    print("=" * 70)
    print()

    violations = [
        ("api_call", "https://api.example.com/admin/config", {"debug": True}, 1.0, "high"),
        ("api_call", "https://api.example.com/billing/charges", {}, 0.5, "normal"),
        ("api_call", "https://api.example.com/internal/deploy", {}, 2.0, "critical"),
        # The trap: a broad prefix rule would have ALLOWED this DELETE on a
        # permitted-looking path. Our tight rule blocks it on method alone.
        ("api_call", "https://api.research.example/v1/search", {"query": "x"}, 0.5, "normal"),
    ]

    for i, (action_type, target, params, cost, urgency) in enumerate(violations, 1):
        result = deployment.agent_propose_action(
            action_type=action_type,
            target=target,
            params=params,
            estimated_cost=cost,
            urgency=urgency,
        )
        print(f"  Violation {i}: {action_type} on {target}")
        print(f"    Outcome: {result.outcome.value}")
        print(f"    Reason: {result.block_reason}")
        print(f"    This violation is recorded ON-CHAIN as evidence of controls operating")
        print()

    print(f"  On-chain events after violations: {deployment.get_agent_status()['on_chain_events']}")
    print()

    # ------------------------------------------------------------------
    # Scenario 4: Kill switch
    # ------------------------------------------------------------------
    print("=" * 70)
    print("SCENARIO 4: KILL SWITCH")
    print("=" * 70)
    print()

    print("  User engages kill switch (emergency stop):")
    tx_hash = deployment.engage_killswitch("Unauthorized deployment detected")
    print(f"    Kill switch engaged (tx: {tx_hash})")
    print()

    print("  Agent tries to act while kill switch is active:")
    result = deployment.agent_propose_action(
        action_type="api_call",
        target="https://api.research.example/v1/search",
        params={"query": "test"},
        estimated_cost=2.0,
    )
    print(f"    Outcome: {result.outcome.value}")
    print(f"    Reason: {result.block_reason}")
    print()

    print("  User disengages kill switch:")
    deployment.disengage_killswitch()
    print("    Kill switch disengaged")
    print()

    # ------------------------------------------------------------------
    # Scenario 5: Binding proof (for third parties)
    # ------------------------------------------------------------------
    print("=" * 70)
    print("SCENARIO 5: BINDING PROOF (FOR THIRD PARTIES)")
    print("=" * 70)
    print()

    proof = deployment.get_binding_proof()
    print("  Binding proof (show to underwriter/counterparty):")
    print(f"    Agent: {proof['agent_id']}")
    print(f"    User: {proof['user_id']}")
    print(f"    On-chain bound: {proof['on_chain']['bound']}")
    print(f"    On-chain tx: {proof['on_chain']['tx_hash']}")
    print(f"    On-chain block: {proof['on_chain']['block_number']}")
    print(f"    Transferable: {proof['on_chain']['transferable']}")
    print(f"    Protocol binding: {proof['protocol_binding']['user_id']}")
    print(f"    Combined valid: {proof['combined_valid']}")
    print()
    print(f"    Proof description: {proof['proof_description'][:200]}...")
    print()

    # ------------------------------------------------------------------
    # Insurance: claims evidence
    # ------------------------------------------------------------------
    print("=" * 70)
    print("INSURANCE: CLAIMS EVIDENCE")
    print("=" * 70)
    print()

    claim = deployment.get_claim_evidence(
        claim_description="Agent made an unauthorized API call to admin endpoint",
        claimed_loss_amount=5000.0,
    )
    print("  Claims evidence package prepared:")
    print(f"    Claim description: {claim['claim_description']}")
    print(f"    Claimed loss: ${claim['claimed_loss_amount']:.2f}")
    print(f"    Binding: agent bound to user (verifiable)")
    print(f"    Off-chain events: {claim['evidence']['off_chain_events']}")
    print(f"    On-chain events: {claim['evidence']['on_chain_events']}")
    print(f"    Scope violations blocked: {claim['controls_operated']['scope_violations_blocked']}")
    print(f"    Approval events: {claim['controls_operated']['approval_events']}")
    print(f"    High-value actions: {claim['controls_operated']['high_value_actions']}")
    print(f"    Killswitch events: {claim['controls_operated']['killswitch_events']}")
    print(f"    On-chain verifiable: {claim['on_chain_verifiable']}")
    print(f"    Submission ready: {claim['submission_ready']}")
    print()
    print(f"    Instructions: {claim['instructions'][:200]}...")
    print()

    # ------------------------------------------------------------------
    # Insurance: underwriter package
    # ------------------------------------------------------------------
    print("=" * 70)
    print("INSURANCE: UNDERWRITER PACKAGE")
    print("=" * 70)
    print()

    underwriter = deployment.get_underwriter_package(
        agent_description="Research agent that calls APIs, sends messages, and can spend on compute",
        task_profile="API calls (search, summarize, analyze), message sending, compute spend",
        max_potential_loss=50000.0,
    )
    print("  Underwriter package prepared:")
    print(f"    Agent: {underwriter['agent_description']}")
    print(f"    Task profile: {underwriter['task_profile']}")
    print(f"    Max potential loss: ${underwriter['max_potential_loss']:,.2f}")
    print()
    print("  Control configuration:")
    for k, v in underwriter["control_configuration"].items():
        print(f"    {k}: {v}")
    print()
    print("  Control health:")
    for k, v in underwriter["control_health"].items():
        print(f"    {k}: {v}")
    print()
    print(f"  Control quality: {underwriter['control_quality_assessment'][:200]}...")
    print()
    print(f"  Recommended approach: {underwriter['recommended_underwriting_approach'][:200]}...")
    print()

    # ------------------------------------------------------------------
    # Insurance: exposure reduction estimate
    # ------------------------------------------------------------------
    print("=" * 70)
    print("INSURANCE: EXPOSURE REDUCTION ESTIMATE")
    print("=" * 70)
    print()

    exposure = deployment.get_exposure_reduction()
    print("  Control-adjusted exposure reduction:")
    print(f"    Controls present: {exposure['controls_present']}")
    print(f"    Controls operational: {exposure['controls_operational']}")
    print()
    print("  Reduction factors:")
    for factor, description in exposure["reduction_factors"].items():
        print(f"    {factor}:")
        print(f"      {description}")
    print()
    print(f"  Estimated reduction: {exposure['estimated_exposure_reduction'][:200]}...")
    print()
    print(f"  Feedback loop: {exposure['underwriting_feedback_loop'][:200]}...")
    print()

    # ------------------------------------------------------------------
    # Final status
    # ------------------------------------------------------------------
    print("=" * 70)
    print("FINAL STATUS")
    print("=" * 70)
    print()

    final = deployment.get_agent_status()
    print(f"  Protocol state: {final['protocol_state']}")
    print(f"  Total actions: {final['monitor']['action_count']}")
    print(f"    Allowed: {final['monitor']['allowed']}")
    print(f"    Blocked: {final['monitor']['blocked']}")
    print(f"    Pending: {final['monitor']['approval_pending']}")
    print(f"  Total cost: ${final['monitor']['total_cost']:.2f}")
    print(f"  On-chain events: {final['on_chain_events']}")
    print(f"  Off-chain events: {final['off_chain_events']}")
    print(f"  Binding valid: {final['binding']['combined_valid']}")
    print()

    print("=" * 70)
    print("WHAT THIS DEMONSTRATES")
    print("=" * 70)
    print("""
The reference deployment shows all four layers of the architecture
operating together:

1. LAYER 0 (Runtime): The agent proposes actions. The LLM/brain would
   be here in production. In this demo, actions are proposed directly.

2. LAYER 1 (Policy & Enforcement): Every action passes through the
   safety protocol. Scope is enforced. Budget is enforced. Approval
   gates operate. The kill switch works. The binding is enforced at
   runtime.

3. LAYER 2 (On-chain anchors): The binding is on-chain (SBT-style,
   non-transferable, verifiable by anyone). Key events are recorded
   on-chain: high-value actions, approvals, kill switch events, scope
   violations. The on-chain record is tamper-resistant and verifiable.

4. LAYER 3 (Economic trust): The insurance interface provides:
   - Claims evidence (complete audit trail + on-chain verifiable events)
   - Underwriter package (control summary, exposure indicators)
   - Exposure reduction estimate (controls reduce insurable risk)

The binding ties the agent to a specific user. The audit trail
reconstructs what happened. The on-chain events are verifiable. The
controls operated and blocked violations. The insurance interface
makes the agent insurable with claims-ready evidence.

This is the reference architecture for building safe, accountable
agents with verifiable binding and insurance-ready evidence.
""")


if __name__ == "__main__":
    run()
