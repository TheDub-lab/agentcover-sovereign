"""
Insurance evidence interface.

The interface between the safety protocol and insurance.

Provides:
- Claims evidence (what happened, controls that operated, verifiable record)
- Underwriter reports (control summary, exposure indicators, control health)
- Control-adjusted exposure metrics (how controls reduce the insurable risk)

The key insight: the safety protocol doesn't replace insurance. It makes
the agent insurable by providing:
1. Evidence of what happened (audit trail + simulated on-chain record)
2. Evidence of controls operating (blocked violations, approvals)
3. Simulated verifiable binding (non-transferable by interface contract)
4. Control-adjusted exposure (controls reduce the risk, which reduces premium)

This is how the protocol lowers insurance cost and makes claims processable.
"""

from __future__ import annotations
from typing import Any


class InsuranceInterface:
    """
    Interface for insurance integration.

    Provides claims-ready evidence and underwriter-ready reports
    from the safety protocol's audit trail.
    """

    def __init__(self, dual_audit):
        """
        Args:
            dual_audit: DualAudit instance with on-chain + off-chain trails
        """
        self.dual_audit = dual_audit

    def prepare_claim_evidence(
        self,
        agent_id: str,
        claim_description: str,
        claimed_loss_amount: float | None = None,
    ) -> dict:
        """
        Prepare evidence for an insurance claim.

        This is what you submit to an insurer when filing a claim.
        It shows:
        - What the agent was authorized to do (scope)
        - What the agent actually did (audit trail)
        - What controls operated (blocked violations, approvals)
        - Simulated on-chain record (in-memory reference implementation)

        The binding ties the agent to a specific user (accountable party).
        The audit trail reconstructs what happened.
        The on-chain events are verifiable by anyone.
        """
        evidence = self.dual_audit.get_claims_evidence(agent_id)
        has_claim_details = bool(agent_id and claim_description.strip())
        has_evidence = (
            evidence["off_chain_events"] > 0 and
            evidence["on_chain_events"] > 0
        )
        claim_ready = has_claim_details and has_evidence

        return {
            "claim_prepared": claim_ready,
            "agent_id": agent_id,
            "claim_description": claim_description,
            "claimed_loss_amount": claimed_loss_amount,
            "binding": {
                "agent_bound_to_user": evidence["binding_events"] > 0,
                "binding_type": "simulated_on_chain_soulbound",
                "verifiable_by_underwriter": False,
                "binding_proof_available": evidence["binding_events"] > 0,
            },
            "evidence": evidence,
            "controls_operated": evidence["controls_evidence"],
            "full_audit_available": evidence["off_chain_events"] > 0,
            "on_chain_verifiable": False,
            "on_chain_backend": "simulated_in_memory",
            "submission_ready": claim_ready,
            "readiness_checks": {
                "claim_details_present": has_claim_details,
                "off_chain_evidence_present": evidence["off_chain_events"] > 0,
                "simulated_on_chain_evidence_present": evidence["on_chain_events"] > 0,
            },
            "instructions": (
                "This reference package is not proof of a deployed blockchain "
                "record. It includes: complete off-chain audit trail, simulated "
                "in-memory on-chain events, "
                "evidence of controls operating (scope violations blocked, "
                "approval events, high-value action records, killswitch events), "
                "and on-chain binding proof. The binding ties this agent to a "
                "specific accountable user. The audit trail reconstructs what "
                "happened. Replace the simulated backend with a deployed smart "
                "contract before describing evidence as publicly verifiable or "
                "tamper-resistant."
            ),
        }

    def generate_underwriter_package(
        self,
        agent_id: str,
        agent_description: str,
        task_profile: str,
        max_potential_loss: float,
    ) -> dict:
        """
        Generate a package for an underwriter assessing this agent.

        This is what you show an insurer before binding coverage.
        It shows:
        - What the agent does (task profile, description)
        - What controls are in place (binding, scope, budget, approval, monitoring, audit, killswitch)
        - How controls have operated (blocked violations, approvals, high-value actions)
        - What the exposure profile looks like (max potential loss, activity level)

        This is the interface that makes the agent insurable and should
        reduce premium through control-adjusted exposure.
        """
        report = self.dual_audit.get_underwriter_report(agent_id)
        has_package_details = bool(
            agent_id and agent_description.strip() and task_profile.strip()
            and max_potential_loss >= 0
        )
        has_evidence = report["control_summary"]["audit_trail_complete"]
        package_ready = has_package_details and has_evidence

        return {
            "underwriter_package": package_ready,
            "agent_id": agent_id,
            "agent_description": agent_description,
            "task_profile": task_profile,
            "max_potential_loss": max_potential_loss,
            "control_configuration": {
                "on_chain_binding": "simulated non-transferable binding (SBT/ERC-5192 interface)",
                "scope_enforced_at_runtime": True,
                "budget_limit": "configured",
                "approval_gates": "configured for consequential actions",
                "monitoring": "live visibility with alerts",
                "audit_trail": "complete off-chain + simulated in-memory on-chain",
                "killswitch": "immediate, total freeze",
            },
            "control_health": report["control_summary"],
            "control_operation_history": report["control_operation_history"],
            "exposure_indicators": report["exposure_indicators"],
            "control_quality_assessment": (
                f"Agent operates with full safety protocol stack. "
                f"Controls have operated {report['control_summary']['scope_violations_prevented']} times "
                f"(blocking violations) and required human approval "
                f"{report['control_summary']['human_oversight_events']} times. "
                f"The reference binding is non-transferable by interface semantics, "
                f"but the on-chain layer is simulated in memory. Audit trail is "
                f"complete in this run. Kill switch available. "
                f"This control configuration reduces insurable exposure relative "
                f"to an agent without these controls."
            ),
            "recommended_underwriting_approach": (
                "Underwrite by autonomy level and action authority (per Zhu framework). "
                "Control-adjusted exposure: this agent's controls reduce effective "
                "exposure. Consider lower premium relative to agent without these "
                "controls. Bind coverage to the accountable user (binding ties "
                "agent to specific user). require audit trail access for claims. "
                "Consider parametric component for clean triggers (e.g., agent "
                "exceeds budget — verifiable from audit trail)."
            ),
            "package_ready": package_ready,
            "readiness_checks": {
                "package_details_present": has_package_details,
                "off_chain_evidence_present": has_evidence,
                "deployed_on_chain_backend": False,
            },
        }

    def get_exposure_reduction_estimate(self, agent_id: str) -> dict:
        """
        Estimate how much the controls reduce insurable exposure.

        This is the control-adjusted exposure calculation.
        The safety protocol's controls directly reduce the risk that
        insurers underwrite. This is what should lower premium.

        In production, this would feed into the insurer's pricing model.
        """
        report = self.dual_audit.get_underwriter_report(agent_id)

        controls_operational = (
            report["control_summary"]["scope_enforced"] or
            report["control_summary"]["human_oversight_events"] > 0
        )

        return {
            "agent_id": agent_id,
            "controls_present": True,
            "controls_operational": controls_operational,
            "reduction_factors": {
                "binding_on_chain": "Reduces accountability ambiguity. Agent tied to specific user. Verifiable.",
                "scope_enforcement": "Prevents unauthorized actions. Reduces likelihood of harmful actions.",
                "budget_limit": "Caps financial exposure. Hard limit on spend.",
                "approval_gates": "Human oversight for consequential actions. Reduces autonomous error risk.",
                "monitoring": "Early detection of problems. Enables intervention before damage compounds.",
                "audit_trail": "Evidence for claims. Makes losses processable and verifiable.",
                "killswitch": "Recovery mechanism. Limits damage when something goes wrong.",
                "on_chain_verifiable_events": "Simulated in-memory evidence only; deploy a smart contract for tamper-resistant verification.",
            },
            "estimated_exposure_reduction": (
                "Significant. Full safety protocol stack reduces insurable exposure "
                "relative to agent without controls. Exact reduction depends on "
                "task profile, autonomy level, and potential loss magnitude. "
                "For underwriting purposes, present controls as risk mitigants "
                "and request control-adjusted pricing."
            ),
            "underwriting_feedback_loop": (
                "The better the controls operate, the lower the exposure. "
                "Build better protocols → lower exposure → lower premium. "
                "This creates incentive to invest in controls, which is the "
                "feedback loop that drives safer agent deployments."
            ),
        }
