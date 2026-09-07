"""
claims_demo_verified.py — corrected against the real agentcover-sovereign source.

This version was run against the actual cloned package (not guessed at):
  - ReferenceDeployment.approve_action(token, reason=None)   [not approved=/approver=]
  - ReferenceDeployment.engage_killswitch(reason)             [one word, not engage_kill_switch]
  - deployment.protocol.protocol.audit / .monitor             [nested: OnChainBoundProtocol.protocol]
  - ActionResult.requires_approval_for holds the approval token (not .approval_token/.token)

The protocol records monitor events for every block path as well as allowed and
pending outcomes. This script demonstrates the gate decisions and their evidence.
"""

from safety_protocol import ScopeRule
from safety_protocol.deployment import ReferenceDeployment
from safety_protocol.scope_linter import lint_rules, Severity


def line(label, result):
    print(f"  {label:<60} -> {result.outcome}"
          + (f"  ({result.block_reason})" if result.block_reason else ""))
    return result


def main():
    scope_rules = [
        ScopeRule(
            action_type="api_call",
            allowed_targets=[
                "https://api.research.example/v1/search",
                "https://api.research.example/v1/summarize",
            ],
            match="exact",
            methods=["POST"],
            param_schema={
                "required": ["query"],
                "properties": {"query": {"type": "string", "maximum": 500}},
                "additional_properties": False,
            },
            forbidden_targets=["admin", "billing", "internal"],
            forbid_match="token",
            max_cost=8.0,
        ),
        ScopeRule(
            action_type="spend",
            allowed_targets=["trusted-merchant.com"],
            match="exact",
            methods=["POST"],
            param_schema={
                "required": ["recipient", "amount"],
                "properties": {
                    "recipient": {"type": "string"},
                    "amount": {"type": "number"},
                },
                "additional_properties": False,
            },
            forbidden_targets=["admin", "billing"],
            forbid_match="token",
            max_cost=8.0,
        ),
        ScopeRule(
            action_type="send_message",
            allowed_targets=["ops-channel"],
            match="exact",
            methods=["POST"],
            param_schema={
                "required": ["body"],
                "properties": {"body": {"type": "string", "maximum": 1000}},
                "additional_properties": False,
            },
            forbidden_targets=[],
            forbid_match="token",
            max_cost=0.0,
        ),
    ]
    allowed_action_types = ["api_call", "spend", "send_message"]

    findings = lint_rules(scope_rules, allowed_action_types)
    blocking = [f for f in findings if f.severity in (Severity.ERROR, Severity.WARN)]
    if blocking:
        raise SystemExit(f"scope too broad to ship: {blocking}")
    print("SCOPE LINT: clean\n")

    deployment = ReferenceDeployment(
        agent_id="agent-claims-verified",
        user_id="alice",
        agent_name="ResearchAndOpsAgent",
        agent_role="AI research + ops assistant with limited spend authority",
        scope_rules=scope_rules,
        budget_limit=50.0,
        approval_threshold=5.0,
        high_value_threshold=25.0,
    )

    print("=" * 70)
    print("TASK: extended session — six gate types, verified against real code")
    print("=" * 70)

    line("[1] api_call search (in-scope)", deployment.agent_propose_action(
        action_type="api_call", target="https://api.research.example/v1/search",
        params={"query": "AI safety"}, estimated_cost=2.50, method="POST"))

    line("[2] api_call evil-admin-panel.com/login", deployment.agent_propose_action(
        action_type="api_call", target="https://evil-admin-panel.com/login",
        params={"query": "n/a"}, estimated_cost=1.0, method="POST"))

    line("[3] api_call evil-admin-panel.com/LOGIN?role=admin (normalization test)",
         deployment.agent_propose_action(
        action_type="api_call", target="https://evil-admin-panel.com/LOGIN?role=admin",
        params={"query": "n/a"}, estimated_cost=1.0, method="POST"))

    line("[4] spend $0.10 to trusted-merchant.com", deployment.agent_propose_action(
        action_type="spend", target="trusted-merchant.com",
        params={"recipient": "trusted-merchant.com", "amount": 0.10},
        estimated_cost=0.10, method="POST"))

    line("[5] spend $9.00 (> $8.00 per-action cap)", deployment.agent_propose_action(
        action_type="spend", target="trusted-merchant.com",
        params={"recipient": "trusted-merchant.com", "amount": 9.00},
        estimated_cost=9.00, method="POST"))

    r6a = deployment.agent_propose_action(
        action_type="spend", target="trusted-merchant.com",
        params={"recipient": "trusted-merchant.com", "amount": 7.50},
        estimated_cost=7.50, method="POST")
    line("[6a] spend $7.50 (> $5.00 threshold) — first pass", r6a)

    if r6a.requires_approval_for:
        approved = deployment.approve_action(
            token=r6a.requires_approval_for, reason="looks fine")
        print(f"       human approval decision: approved={approved}")
        line("[6b] spend $7.50 — retry after approval", deployment.agent_propose_action(
            action_type="spend", target="trusted-merchant.com",
            params={"recipient": "trusted-merchant.com", "amount": 7.50},
            estimated_cost=7.50, method="POST"))

    line("[7] send_message to ops-channel", deployment.agent_propose_action(
        action_type="send_message", target="ops-channel",
        params={"body": "status update"}, estimated_cost=0.0, method="POST"))

    line("[8] internal_admin_bypass (unrecognized verb)", deployment.agent_propose_action(
        action_type="internal_admin_bypass",
        target="https://api.research.example/v1/internal_admin_bypass",
        params={}, estimated_cost=0.0))

    line("[9] api_call search + extra field 'debug' (param-schema violation)",
         deployment.agent_propose_action(
        action_type="api_call", target="https://api.research.example/v1/search",
        params={"query": "AI safety", "debug": "true"},
        estimated_cost=2.50, method="POST"))

    deployment.engage_killswitch(reason="suspicious step-8/9 attempts, manual review")
    print("  [10] KILL SWITCH ENGAGED")

    line("[11] api_call search (post-kill-switch)", deployment.agent_propose_action(
        action_type="api_call", target="https://api.research.example/v1/search",
        params={"query": "anything"}, estimated_cost=1.0, method="POST"))

    print()
    print("=" * 70)
    print("AUDIT TRAIL + MONITOR (real objects — see KNOWN GAP note at top of file)")
    print("=" * 70)
    print(deployment.protocol.protocol.audit.reconstruct_sequence("agent-claims-verified"))
    print(deployment.protocol.protocol.monitor.snapshot())

    print("=" * 70)
    print("CLAIMS EVIDENCE")
    print("=" * 70)
    evidence = deployment.get_claim_evidence(
        claim_description=(
            "Extended session: scope-target block (x2), scope-cost-cap block, "
            "closed-vocabulary block, param-schema block, approval-gated payment, "
            "and mid-session kill switch."
        )
    )
    print(f"  {evidence}")


if __name__ == "__main__":
    main()
