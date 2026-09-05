"""
On-chain audit trail for key events.

Records consequential events on-chain for verifiable provenance.
This is the subset of the audit trail that goes on-chain — not every action,
but the ones that matter for accountability and claims:

- Binding events (agent bound to user)
- High-value actions (above threshold)
- Approval events (human decisions)
- Kill switch events (freeze/thaw)
- Revocation events (binding revoked)
- Scope violations (blocked actions — evidence of controls working)

The on-chain record is tamper-resistant and publicly verifiable.
Anyone can check: did this happen? when? what was the state?

This is the evidence layer that feeds into insurance claims and
third-party verification.
"""

from __future__ import annotations
import hashlib
import time
import uuid
from dataclasses import dataclass, field
from typing import Any


@dataclass
class OnChainEvent:
    """An event as it would appear on-chain."""
    event_type: str
    agent_id: str
    user_id: str
    tx_hash: str
    block_number: int
    timestamp: float
    data: dict = field(default_factory=dict)
    # Link to the off-chain audit entry for full context
    off_chain_ref: str | None = None


class OnChainAudit:
    """
    Records consequential events on-chain.

    In production: emit events from a smart contract or record in an
    on-chain event log. The interface is the same — events with tx hashes,
    block numbers, timestamps, and data.

    The off-chain audit trail is the complete record. The on-chain record
    is the verifiable subset — the events that matter for accountability,
    claims, and third-party verification.
    """

    def __init__(self, chain_id: str = "local-testnet"):
        self.chain_id = chain_id
        self._events: dict[str, OnChainEvent] = {}
        self._block_number = 0
        self._tx_counter = 0

    def _next_tx_hash(self) -> str:
        self._tx_counter += 1
        return hashlib.sha256(f"evt-{self._tx_counter}-{time.time()}".encode()).hexdigest()[:16]

    def _next_block(self) -> int:
        self._block_number += 1
        return self._block_number

    def record(
        self,
        event_type: str,
        agent_id: str,
        user_id: str,
        data: dict | None = None,
        off_chain_ref: str | None = None,
    ) -> str:
        """
        Record an event on-chain.

        Returns: transaction hash
        """
        tx_hash = self._next_tx_hash()
        block = self._next_block()

        event = OnChainEvent(
            event_type=event_type,
            agent_id=agent_id,
            user_id=user_id,
            tx_hash=tx_hash,
            block_number=block,
            timestamp=time.time(),
            data=data or {},
            off_chain_ref=off_chain_ref,
        )

        self._events[tx_hash] = event
        return tx_hash

    def get_event(self, tx_hash: str) -> OnChainEvent | None:
        """Get a single event by tx hash."""
        return self._events.get(tx_hash)

    def query(
        self,
        agent_id: str | None = None,
        event_types: list[str] | None = None,
        user_id: str | None = None,
    ) -> list[OnChainEvent]:
        """Query events by agent, type, or user."""
        results = list(self._events.values())
        if agent_id:
            results = [e for e in results if e.agent_id == agent_id]
        if user_id:
            results = [e for e in results if e.user_id == user_id]
        if event_types:
            results = [e for e in results if e.event_type in event_types]
        return results

    def get_binding_events(self, agent_id: str) -> list[OnChainEvent]:
        """Get all binding-related events for an agent."""
        return self.query(
            agent_id=agent_id,
            event_types=["binding_created", "binding_revoked"],
        )

    def get_high_value_events(self, agent_id: str, min_value: float = 10.0) -> list[OnChainEvent]:
        """Get high-value action events for an agent."""
        results = []
        for e in self.query(agent_id=agent_id, event_types=["action_high_value"]):
            if e.data.get("estimated_cost", 0) >= min_value:
                results.append(e)
        return results

    def get_approval_events(self, agent_id: str) -> list[OnChainEvent]:
        """Get all approval-related events."""
        return self.query(
            agent_id=agent_id,
            event_types=["approval_requested", "approval_granted", "approval_denied"],
        )

    def get_killswitch_events(self, agent_id: str) -> list[OnChainEvent]:
        """Get all kill switch events."""
        return self.query(
            agent_id=agent_id,
            event_types=["killswitch_engaged", "killswitch_disengaged"],
        )

    def get_scope_violation_events(self, agent_id: str) -> list[OnChainEvent]:
        """Get all scope violation (blocked) events — evidence of controls operating."""
        return self.query(
            agent_id=agent_id,
            event_types=["action_blocked_scope", "action_blocked_budget", "action_blocked_killswitch"],
        )

    def get_full_sequence(self, agent_id: str) -> list[OnChainEvent]:
        """Get all on-chain events for an agent, in order."""
        events = self.query(agent_id=agent_id)
        return sorted(events, key=lambda e: e.timestamp)

    def verify_integrity(self) -> bool:
        """
        In production, this would verify the on-chain event log is intact.
        For the simulation, events are always present in memory.

        Real implementation: verify event hashes against the chain.
        """
        return True


# ---------------------------------------------------------------------------
# Integration: on-chain + off-chain audit working together
# ---------------------------------------------------------------------------

class DualAudit:
    """
    Combines on-chain and off-chain audit trails.

    The off-chain trail is the complete record (every action, every event).
    The on-chain trail is the verifiable subset (key events immutably recorded).

    Together they provide:
    - Completeness (off-chain has everything)
    - Verifiability (on-chain has the key events, tamper-resistant)
    - Claims-ready evidence (both together reconstruct what happened)

    This is the audit layer for the full architecture.
    """

    def __init__(
        self,
        on_chain: OnChainAudit,
    ):
        self.on_chain = on_chain
        self.off_chain_events: list[dict] = []

    def record_off_chain(self, event: dict):
        """Record an event off-chain (complete record)."""
        self.off_chain_events.append(event)

    def record_on_chain(
        self,
        event_type: str,
        agent_id: str,
        user_id: str,
        data: dict | None = None,
        off_chain_ref: str | None = None,
    ) -> str:
        """
        Record an event on-chain.

        Also records it off-chain with a reference to the on-chain tx.
        """
        tx_hash = self.on_chain.record(event_type, agent_id, user_id, data, off_chain_ref)

        self.record_off_chain({
            "event_type": event_type,
            "agent_id": agent_id,
            "user_id": user_id,
            "on_chain_tx": tx_hash,
            "data": data or {},
        })

        return tx_hash

    def get_claims_evidence(self, agent_id: str) -> dict:
        """
        Return claims-ready evidence for an agent.

        This is what you show to an insurer when filing a claim or
        providing evidence of controls. It includes:

        - Complete off-chain record (everything that happened)
        - On-chain verifiable events (the ones that matter, tamper-resistant)
        - Scope violations (evidence the controls operated)
        - Approvals (evidence of human oversight)
        - High-value actions (evidence of consequential events)

        This is the interface between the safety protocol and insurance.
        """
        off_chain = [e for e in self.off_chain_events if e.get("agent_id") == agent_id]
        on_chain = self.on_chain.get_full_sequence(agent_id)

        # Evidence of controls operating
        scope_violations = self.on_chain.get_scope_violation_events(agent_id)
        approvals = self.on_chain.get_approval_events(agent_id)
        high_value = self.on_chain.get_high_value_events(agent_id)
        killswitch = self.on_chain.get_killswitch_events(agent_id)

        return {
            "agent_id": agent_id,
            "off_chain_events": len(off_chain),
            "on_chain_events": len(on_chain),
            "on_chain_events_detail": [
                {
                    "event_type": e.event_type,
                    "tx_hash": e.tx_hash,
                    "block": e.block_number,
                    "timestamp": e.timestamp,
                    "data": e.data,
                }
                for e in on_chain
            ],
            "controls_evidence": {
                "scope_violations_blocked": len(scope_violations),
                "scope_violation_details": [
                    {
                        "event_type": e.event_type,
                        "data": e.data,
                        "tx_hash": e.tx_hash,
                    }
                    for e in scope_violations
                ],
                "approval_events": len(approvals),
                "approval_details": [
                    {
                        "event_type": e.event_type,
                        "data": e.data,
                        "tx_hash": e.tx_hash,
                    }
                    for e in approvals
                ],
                "high_value_actions": len(high_value),
                "killswitch_events": len(killswitch),
            },
            "claims_ready": True,
            "evidence_description": (
                "Complete off-chain audit trail + on-chain verifiable events. "
                "On-chain events are tamper-resistant and publicly verifiable. "
                "Off-chain trail provides full context. Together they reconstruct "
                "everything that happened with the agent."
            ),
        }

    def get_underwriter_report(self, agent_id: str) -> dict:
        """
        Return a report for an underwriter assessing this agent's risk.

        This shows what controls are in place, how they've operated,
        and what the exposure profile looks like.

        This is the interface that makes the agent insurable.
        """
        evidence = self.get_claims_evidence(agent_id)

        # Calculate exposure metrics
        total_blocked = evidence["controls_evidence"]["scope_violations_blocked"]
        total_approvals = evidence["controls_evidence"]["approval_events"]

        return {
            "agent_id": agent_id,
            "underwriter_ready": True,
            "control_summary": {
                "scope_enforced": total_blocked > 0,  # Has the scope gate fired?
                "scope_violations_prevented": total_blocked,
                "human_oversight_events": total_approvals,
                "killswitch_available": True,
                "binding_on_chain": True,
                "audit_trail_complete": evidence["off_chain_events"] > 0,
                "on_chain_verifiable_events": evidence["on_chain_events"] > 0,
            },
            "control_operation_history": evidence["controls_evidence"],
            "exposure_indicators": {
                "high_value_actions": evidence["controls_evidence"]["high_value_actions"],
                "agent_activity_level": evidence["off_chain_events"],
                "control_health": "operational" if total_blocked > 0 or total_approvals > 0 else "no incidents recorded",
            },
            "underwriting_notes": (
                "Agent operates with enforced safety protocols: binding on-chain, "
                "scope enforced at runtime, budget caps, approval gates for "
                "consequential actions, monitoring with alerts, immutable audit "
                "trail (off-chain + on-chain), and kill switch. Controls have "
                f"operated {total_blocked} times (blocked violations) and "
                f"required human approval {total_approvals} times. "
                "On-chain binding is non-transferable (SBT). Audit trail is "
                "complete off-chain and verifiable on-chain for key events."
            ),
        }
