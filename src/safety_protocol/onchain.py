"""
On-chain binding for agent identity.

In production, this uses ERC-5192 (soulbound token) or ERC-8004 (agent registry)
on a real chain. For this reference architecture, we simulate the on-chain layer
with in-memory state that has the same interface and semantics.

The key design: binding is verifiable, non-transferable, and public.
Anyone can check the chain and see: this agent is bound to this user.
The binding cannot be transferred (SBT property). The binding can be revoked
by the user (revocation is recorded on-chain).

Interface:
- bind_agent(agent_id, user_id, metadata) -> tx_hash
- verify_binding(agent_id) -> {bound_to, revoked, tx_hash, block_number}
- revoke_binding(agent_id, reason) -> tx_hash
- get_agent_binding(agent_id) -> binding record
"""

from __future__ import annotations
import hashlib
import time
import uuid
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Simulated on-chain state (same interface as real chain in production)
# ---------------------------------------------------------------------------

@dataclass
class OnChainBinding:
    """A binding record as it would appear on-chain."""
    agent_id: str
    user_id: str
    tx_hash: str
    block_number: int
    timestamp: float
    metadata: dict = field(default_factory=dict)
    revoked: bool = False
    revocation_tx: str | None = None
    revocation_block: int | None = None
    revocation_reason: str | None = None
    revocation_timestamp: float | None = None
    # SBT property: non-transferable
    transferable: bool = False


class OnChainBindingRegistry:
    """
    Simulates an on-chain binding registry (ERC-5192 / ERC-8004).

    In production, this would be a smart contract. The interface is the same.
    The binding is verifiable by anyone who can read the chain.
    """

    def __init__(self):
        self._bindings: dict[str, OnChainBinding] = {}
        self._block_number = 0
        self._tx_counter = 0

    def _next_tx_hash(self) -> str:
        self._tx_counter += 1
        return hashlib.sha256(f"tx-{self._tx_counter}-{time.time()}".encode()).hexdigest()[:16]

    def _next_block(self) -> int:
        self._block_number += 1
        return self._block_number

    def bind_agent(
        self,
        agent_id: str,
        user_id: str,
        metadata: dict | None = None,
    ) -> str:
        """
        Create a non-transferable binding on-chain.

        In production: mint an ERC-5192 soulbound token or register in ERC-8004.
        The binding is permanent for this agent_id (non-transferable).
        Only the user can revoke.

        Returns: transaction hash
        """
        if agent_id in self._bindings and not self._bindings[agent_id].revoked:
            raise ValueError(f"Agent {agent_id} already bound and not revoked")

        tx_hash = self._next_tx_hash()
        block = self._next_block()

        self._bindings[agent_id] = OnChainBinding(
            agent_id=agent_id,
            user_id=user_id,
            tx_hash=tx_hash,
            block_number=block,
            timestamp=time.time(),
            metadata=metadata or {},
            revoked=False,
        )

        return tx_hash

    def verify_binding(self, agent_id: str) -> dict:
        """
        Verify the binding for an agent.

        Returns a record anyone can verify:
        - Is the agent bound?
        - To whom?
        - When?
        - Has it been revoked?
        - On which block (for verifiability)?

        In production: read from the chain. Anyone can do this.
        """
        binding = self._bindings.get(agent_id)
        if binding is None:
            return {
                "bound": False,
                "agent_id": agent_id,
                "reason": "No binding found",
            }

        return {
            "bound": not binding.revoked,
            "agent_id": binding.agent_id,
            "user_id": binding.user_id,
            "tx_hash": binding.tx_hash,
            "block_number": binding.block_number,
            "timestamp": binding.timestamp,
            "metadata": binding.metadata,
            "revoked": binding.revoked,
            "revocation_tx": binding.revocation_tx,
            "revocation_block": binding.revocation_block,
            "revocation_reason": binding.revocation_reason,
            "revocation_timestamp": binding.revocation_timestamp,
            "transferable": binding.transferable,
        }

    def revoke_binding(self, agent_id: str, reason: str) -> str:
        """
        Revoke a binding.

        In production: user signs a revocation transaction.
        The revocation is recorded on-chain. Anyone can verify it happened.
        """
        binding = self._bindings.get(agent_id)
        if binding is None or binding.revoked:
            raise ValueError(f"Agent {agent_id} not bound or already revoked")

        tx_hash = self._next_tx_hash()
        block = self._next_block()

        binding.revoked = True
        binding.revocation_tx = tx_hash
        binding.revocation_block = block
        binding.revocation_reason = reason
        binding.revocation_timestamp = time.time()

        return tx_hash

    def get_all_bindings(self) -> list[dict]:
        """Return all bindings (for verification/indexing)."""
        return [self.verify_binding(aid) for aid in self._bindings]


# ---------------------------------------------------------------------------
# Integration with the safety protocol
# ---------------------------------------------------------------------------

class OnChainBoundProtocol:
    """
    A SafetyProtocol with on-chain binding.

    The agent's binding is anchored on-chain (SBT / ERC-8004 in production).
    The protocol enforces at runtime. Together they make the binding:
    - Verifiable (anyone can check the chain)
    - Enforced (the protocol blocks actions if binding is revoked)
    - Non-transferable (SBT property)
    - Revocable by the user (revocation recorded on-chain)

    This is the "binding" layer of the full architecture.
    """

    def __init__(
        self,
        agent_id: str,
        user_id: str,
        on_chain_registry: OnChainBindingRegistry,
        scope_rules=None,
        budget_limit=None,
        approval_threshold_cost=10.0,
        allowed_action_types=None,
    ):
        from .protocol import SafetyProtocol

        self.agent_id = agent_id
        self.user_id = user_id
        self.on_chain = on_chain_registry

        # Create the on-chain binding
        tx_hash = self.on_chain.bind_agent(agent_id, user_id, {
            "protocol_version": "0.2.0",
            "binding_type": "soulbound",
        })

        # Create the runtime enforcement protocol
        self.protocol = SafetyProtocol(
            agent_id=agent_id,
            user_id=user_id,
            scope_rules=scope_rules,
            budget_limit=budget_limit,
            approval_threshold_cost=approval_threshold_cost,
            allowed_action_types=allowed_action_types,
        )

        self. binding_tx = tx_hash
        self. binding_verified = True

    def verify_binding_on_chain(self) -> dict:
        """Verify the binding from the on-chain registry."""
        return self.on_chain.verify_binding(self.agent_id)

    def revoke_binding(self, reason: str) -> str:
        """
        Revoke the binding (user action).

        This revokes both on-chain and at the protocol level.
        The agent can no longer act.
        """
        tx_hash = self.on_chain.revoke_binding(self.agent_id, reason)
        self.protocol.revoke_binding(reason)
        return tx_hash

    def check_binding(self) -> bool:
        """Is the binding still valid (on-chain + protocol)?"""
        on_chain = self.on_chain.verify_binding(self.agent_id)
        protocol_ok = self.protocol.verify_binding()
        return on_chain.get("bound", False) and protocol_ok

    def get_pending_approvals(self) -> list[dict]:
        """What's waiting for human decision?"""
        return self.protocol.get_pending_approvals()

    def get_binding_proof(self) -> dict:
        """
        Return a binding proof that can be shown to third parties.

        This is what you show to an underwriter, a counterparty, or
        anyone who needs to verify the agent is bound to this user.

        In production, this includes the on-chain tx hash, block number,
        and the user's cryptographic signature.
        """
        on_chain = self.on_chain.verify_binding(self.agent_id)
        return {
            "agent_id": self.agent_id,
            "user_id": self.user_id,
            "on_chain": on_chain,
            "protocol_binding": self.protocol.binding,
            "combined_valid": self.check_binding(),
            "proof_type": "on_chain_soulbound",
            "proof_description": (
                "This agent is non-transferably bound to this user. "
                "The binding is recorded on-chain and enforced at runtime. "
                "Anyone can verify: check the on-chain registry for this "
                "agent_id. The binding is non-transferable (SBT property). "
                "Only the user can revoke."
            ),
        }
