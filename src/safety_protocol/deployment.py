"""
Reference Deployment: Full Safety Protocol Architecture.

This is the reference architecture showing all four layers operating together:

Layer 0: Runtime (off-chain) — the agent's brain, LLM, reasoning
Layer 1: Policy & Enforcement (safety protocol) — binding, scope, budget, approval, monitoring, audit, killswitch
Layer 2: On-chain anchors — SBT binding, on-chain audit for key events, verifiable record
Layer 3: Economic trust — insurance evidence interface, underwriter reports, claims evidence

This reference deployment shows a single agent operating through the full stack.
Every action passes through the protocol. Key events are recorded on-chain.
The insurance interface provides claims-ready evidence and underwriter reports.

In production:
- Layer 0: Real LLM (OpenAI, Anthropic, local model)
- Layer 1: This safety protocol (Python library)
- Layer 2: Real chain (Ethereum, L2, etc.) with ERC-5192 SBT + ERC-8004 + x402
- Layer 3: Real insurance product (HSB, AXA XL, etc.) with this evidence interface

This reference deployment demonstrates the architecture and the integration points.
"""

from __future__ import annotations
from safety_protocol import (
    SafetyProtocol,
    BoundAgent,
    ScopeRule,
)
from .onchain import OnChainBindingRegistry, OnChainBoundProtocol
from .onchain_audit import OnChainAudit, DualAudit
from .insurance import InsuranceInterface


class ReferenceDeployment:
    """
    A complete reference deployment of the safety protocol architecture.

    This demonstrates the full stack:
    - Agent bound to user (on-chain SBT + runtime binding)
    - Every action through the safety protocol
    - Key events on-chain (binding, high-value actions, approvals, kill switch, scope violations)
    - Insurance evidence interface (claims evidence, underwriter reports)

    Usage:
        deployment = ReferenceDeployment(
            agent_id="agent-001",
            user_id="alice",
            agent_name="ResearchAgent",
            agent_role="AI research assistant with safety protocols",
        )

        # Agent proposes an action — full stack enforces
        result = deployment.agent_propose_action(
            action_type="api_call",
            target="https://api.example.com/v1/search",
            params={"query": "AI safety 2026"},
            estimated_cost=2.50,
        )

        # Check binding (verifiable by anyone)
        binding = deployment.get_binding_proof()

        # Get claims evidence (for insurance)
        claim_evidence = deployment.get_claim_evidence(
            claim_description="Agent made incorrect API call resulting in data loss",
        )

        # Get underwriter report (for binding coverage)
        underwriter = deployment.get_underwriter_package(
            agent_description="Research agent that calls APIs and sends messages",
            task_profile="API calls, message sending, limited compute",
            max_potential_loss=5000.0,
        )
    """

    def __init__(
        self,
        agent_id: str,
        user_id: str,
        agent_name: str = "Agent",
        agent_role: str = "Safety-protected agent",
        scope_rules=None,
        budget_limit=100.0,
        approval_threshold=10.0,
        high_value_threshold=25.0,
        allowed_action_types=None,
    ):
        """
        Initialize the full reference deployment.

        Args:
            agent_id: Unique agent identifier
            user_id: The accountable user this agent is bound to
            agent_name: Descriptive name for the agent
            agent_role: What the agent does
            scope_rules: List of ScopeRule objects
            budget_limit: Maximum total spend
            approval_threshold: Actions above this cost need approval
            high_value_threshold: Actions above this are recorded on-chain
            allowed_action_types: Closed vocabulary of permitted action verbs
        """
        # Layer 2: On-chain anchors
        self.on_chain_registry = OnChainBindingRegistry()
        self.on_chain_audit = OnChainAudit(chain_id="reference-deployment")

        # Layer 1: Policy & enforcement — with on-chain binding
        self.protocol = OnChainBoundProtocol(
            agent_id=agent_id,
            user_id=user_id,
            on_chain_registry=self.on_chain_registry,
            scope_rules=scope_rules,
            budget_limit=budget_limit,
            approval_threshold_cost=approval_threshold,
            allowed_action_types=allowed_action_types,
        )

        # Dual audit: off-chain complete + on-chain verifiable
        self.dual_audit = DualAudit(self.on_chain_audit)

        # Layer 3: Insurance interface
        self.insurance = InsuranceInterface(self.dual_audit)

        # Agent metadata
        self.agent_id = agent_id
        self.user_id = user_id
        self.agent_name = agent_name
        self.agent_role = agent_role
        self.high_value_threshold = high_value_threshold

        # Wire the protocol to record key events on-chain
        self._wire_on_chain_events()

        # Record the binding event on-chain (in addition to the SBT)
        self.dual_audit.record_on_chain(
            event_type="binding_created",
            agent_id=agent_id,
            user_id=user_id,
            data={
                "agent_name": agent_name,
                "agent_role": agent_role,
                "binding_type": "on_chain_soulbound",
                "protocol_version": "0.2.0",
            },
        )

    def _wire_on_chain_events(self):
        """
        Wire the protocol's audit trail to also record on-chain for key events.

        This is the integration point between the runtime protocol and the
        on-chain audit layer. Every action that passes through the protocol
        is recorded off-chain (complete). Key events are also recorded on-chain
        (verifiable).
        """
        # Access the protocol's internal audit and monitor
        protocol_audit = self.protocol.protocol.audit
        protocol_monitor = self.protocol.protocol.monitor

        # Override the monitor's record_action to also record on-chain for key events
        original_record = protocol_monitor.record_action

        def wrapped_record_action(result, request):
            original_record(result, request)

            # Record on-chain for key event types
            if result.outcome == result.outcome.ALLOWED and request.estimated_cost >= self.high_value_threshold:
                # High-value action — record on-chain
                self.dual_audit.record_on_chain(
                    event_type="action_high_value",
                    agent_id=self.agent_id,
                    user_id=self.user_id,
                    data={
                        "request_id": request.request_id,
                        "action_type": request.action_type,
                        "target": request.target,
                        "estimated_cost": request.estimated_cost,
                        "urgency": request.urgency,
                    },
                    off_chain_ref=f"action-{request.request_id}",
                )

            elif result.outcome == result.outcome.PENDING_APPROVAL:
                # Approval requested — record on-chain
                self.dual_audit.record_on_chain(
                    event_type="approval_requested",
                    agent_id=self.agent_id,
                    user_id=self.user_id,
                    data={
                        "request_id": request.request_id,
                        "action_type": request.action_type,
                        "target": request.target,
                        "estimated_cost": request.estimated_cost,
                        "urgency": request.urgency,
                    },
                )

            elif result.outcome != result.outcome.ALLOWED:
                # Blocked action — record on-chain (evidence of controls operating)
                event_type_map = {
                    result.outcome.BLOCKED_SCOPE: "action_blocked_scope",
                    result.outcome.BLOCKED_BUDGET: "action_blocked_budget",
                    result.outcome.BLOCKED_KILLSWITCH: "action_blocked_killswitch",
                }
                event_type = event_type_map.get(result.outcome, "action_blocked")
                self.dual_audit.record_on_chain(
                    event_type=event_type,
                    agent_id=self.agent_id,
                    user_id=self.user_id,
                    data={
                        "request_id": request.request_id,
                        "action_type": request.action_type,
                        "target": request.target,
                        "block_reason": result.block_reason,
                        "estimated_cost": request.estimated_cost,
                    },
                )

            # Also record all allowed actions off-chain (complete record)
            if result.outcome == result.outcome.ALLOWED:
                self.dual_audit.record_off_chain({
                    "event_type": "action_allowed",
                    "agent_id": self.agent_id,
                    "user_id": self.user_id,
                    "on_chain_tx": None,  # Only high-value goes on-chain
                    "data": {
                        "request_id": request.request_id,
                        "action_type": request.action_type,
                        "target": request.target,
                        "estimated_cost": request.estimated_cost,
                        "urgency": request.urgency,
                    },
                })

        protocol_monitor.record_action = wrapped_record_action

    # ------------------------------------------------------------------
    # Public API: agent actions through the full stack
    # ------------------------------------------------------------------

    def agent_propose_action(
        self,
        action_type: str,
        target: str,
        params: dict | None = None,
        estimated_cost: float = 0.0,
        urgency: str = "normal",
        method: str | None = None,
    ):
        """
        The agent proposes an action. The full stack enforces.

        This is the single entry point for agent actions. Every action
        passes through: on-chain binding verification → scope → budget →
        approval → execution. Key events are recorded on-chain.

        Returns: ActionResult (same as the protocol, with full stack applied)
        """
        request = self.protocol.protocol.execute(ActionRequest(
            action_type=action_type,
            target=target,
            params=params or {},
            estimated_cost=estimated_cost,
            urgency=urgency,
            method=method,
        ))

        return request

    def approve_action(self, token: str, reason: str | None = None) -> bool:
        """Human approves a pending action."""
        return self.protocol.protocol.decide_approval(
            token=token,
            approved=True,
            approver=self.user_id,
            reason=reason,
        )

    def deny_action(self, token: str, reason: str) -> bool:
        """Human denies a pending action."""
        return self.protocol.protocol.decide_approval(
            token=token,
            approved=False,
            approver=self.user_id,
            reason=reason,
        )

    def engage_killswitch(self, reason: str) -> str:
        """Engage the kill switch (user action). Records on-chain."""
        tx_hash = self.protocol.protocol.engage_killswitch(reason)

        self.dual_audit.record_on_chain(
            event_type="killswitch_engaged",
            agent_id=self.agent_id,
            user_id=self.user_id,
            data={"reason": reason},
        )

        return tx_hash

    def disengage_killswitch(self):
        """Disengage the kill switch."""
        self.protocol.protocol.disengage_killswitch()

        self.dual_audit.record_on_chain(
            event_type="killswitch_disengaged",
            agent_id=self.agent_id,
            user_id=self.user_id,
            data={},
        )

    def revoke_agent(self, reason: str) -> str:
        """
        Revoke the agent's authority entirely.

        Revokes on-chain binding + protocol binding.
        Records on-chain. Agent can no longer act.
        """
        tx_hash = self.protocol.revoke_binding(reason)

        self.dual_audit.record_on_chain(
            event_type="binding_revoked",
            agent_id=self.agent_id,
            user_id=self.user_id,
            data={"reason": reason},
        )

        return tx_hash

    # ------------------------------------------------------------------
    # Verification & evidence
    # ------------------------------------------------------------------

    def get_binding_proof(self) -> dict:
        """Get the binding proof (for third parties, underwriters, counterparties)."""
        return self.protocol.get_binding_proof()

    def verify_agent_on_chain(self) -> dict:
        """Verify the agent's binding on-chain (anyone can do this)."""
        return self.on_chain_registry.verify_binding(self.agent_id)

    def get_agent_status(self) -> dict:
        """Get comprehensive agent status."""
        return {
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "user_id": self.user_id,
            "binding": self.get_binding_proof(),
            "protocol_state": self.protocol.protocol._state.value,
            "monitor": self.protocol.protocol.monitor.get_status(),
            "pending_approvals": self.protocol.get_pending_approvals(),
            "on_chain_events": len(self.on_chain_audit.get_full_sequence(self.agent_id)),
            "off_chain_events": len(self.dual_audit.off_chain_events),
        }

    def get_claim_evidence(
        self,
        claim_description: str,
        claimed_loss_amount: float | None = None,
    ) -> dict:
        """Get claims-ready evidence (for insurance)."""
        return self.insurance.prepare_claim_evidence(
            agent_id=self.agent_id,
            claim_description=claim_description,
            claimed_loss_amount=claimed_loss_amount,
        )

    def get_underwriter_package(
        self,
        agent_description: str,
        task_profile: str,
        max_potential_loss: float,
    ) -> dict:
        """Get underwriter-ready package (for binding coverage)."""
        return self.insurance.generate_underwriter_package(
            agent_id=self.agent_id,
            agent_description=agent_description,
            task_profile=task_profile,
            max_potential_loss=max_potential_loss,
        )

    def get_exposure_reduction(self) -> dict:
        """Get control-adjusted exposure estimate."""
        return self.insurance.get_exposure_reduction_estimate(self.agent_id)

    def get_full_audit(self) -> dict:
        """Get the complete audit trail (off-chain + on-chain)."""
        return self.dual_audit.get_claims_evidence(self.agent_id)


# Import for the wrapped_record_action
from .core import ActionRequest, ActionResult
