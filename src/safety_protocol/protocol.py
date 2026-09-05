"""
Safety protocol enforcement layer and bound agent.

The SafetyProtocol is the enforcement layer between the agent and the world.
Every action the agent wants to take passes through this protocol. The protocol
checks: binding, scope, budget, approval, kill switch. Nothing executes without
passing through.

This is NOT a prompt instruction to the agent. This is infrastructure. The agent
cannot talk its way around it.

The BoundAgent is unambiguously tied to a user. It operates through the SafetyProtocol.
Every action the agent takes is attributable to the user.
"""

from __future__ import annotations
import uuid
import time
from typing import Any
from .core import (
    ActionOutcome,
    ProtocolState,
    ActionRequest,
    ActionResult,
    ScopeRule,
    AuditTrail,
    Monitor,
    target_matches,
    validate_params,
)


class SafetyProtocol:
    """
    The enforcement layer that sits between the agent and the world.

    Every action the agent wants to take passes through this protocol.
    The protocol checks: binding, scope, budget, approval, kill switch.
    Nothing executes without passing through.

    This is NOT a prompt instruction to the agent. This is infrastructure.
    The agent cannot talk its way around it.
    """

    def __init__(
        self,
        agent_id: str,
        user_id: str,
        scope_rules: list[ScopeRule] | None = None,
        budget_limit: float | None = None,
        approval_threshold_cost: float = 10.0,
        audit: AuditTrail | None = None,
        monitor: Monitor | None = None,
        allowed_action_types: list[str] | None = None,
    ):
        """
        Args:
            agent_id: Unique identifier for this agent
            user_id: The user this agent is bound to (THE binding)
            scope_rules: List of ScopeRule objects defining allowed actions
            budget_limit: Maximum total spend across all actions (None = unlimited)
            approval_threshold_cost: Actions costing this much or more need approval
            audit: AuditTrail for immutable logging (auto-created if None)
            monitor: Monitor for real-time visibility (auto-created if None)
            allowed_action_types: Closed vocabulary of permitted action verbs.
                An action whose action_type is NOT in this list is blocked
                regardless of scope rules. If None, the set of action_types
                referenced by scope_rules is used as the vocabulary. Passing
                an explicit list is recommended — it forces you to name what
                the agent can do.
        """
        self.agent_id = agent_id
        self.user_id = user_id
        self.scope_rules = scope_rules or []
        self.budget_limit = budget_limit
        self.approval_threshold_cost = approval_threshold_cost
        self.audit = audit or AuditTrail()
        self.monitor = monitor or Monitor(self.audit, agent_id)
        self._state = ProtocolState.ACTIVE
        self._spent = 0.0
        self._pending_approvals: dict[str, ActionRequest] = {}
        # Approved intents: (target, cost-cents) -> expiry ts. When a human
        # approves an action, the matching retry is allowed for a short window
        # so the agent can actually proceed after sign-off. Per-intent, not
        # a blanket allow — a different target or cost still needs approval.
        self._approved_intents: dict[tuple, float] = {}
        self._start_time = time.time()

        # Closed action vocabulary. Deny-by-default at the verb level:
        # a verb not in this set is blocked before any rule is consulted.
        if allowed_action_types is not None:
            self.allowed_action_types = list(allowed_action_types)
        else:
            self.allowed_action_types = sorted({
                r.action_type for r in self.scope_rules if r.action_type
            })

        # Log initialization
        self.audit.append("protocol_initialized", agent_id, {
            "user_id": user_id,
            "scope_rules_count": len(self.scope_rules),
            "budget_limit": budget_limit,
            "approval_threshold": approval_threshold_cost,
            "allowed_action_types": self.allowed_action_types,
        })

    # ------------------------------------------------------------------
    # Binding
    # ------------------------------------------------------------------

    @property
    def binding(self) -> dict:
        """Return the binding record."""
        return {
            "agent_id": self.agent_id,
            "user_id": self.user_id,
            "state": self._state.value,
            "protocol_version": "0.1.0",
        }

    def verify_binding(self) -> bool:
        """Is this agent still bound to a valid user?"""
        return self._state != ProtocolState.REVOKED

    def revoke_binding(self, reason: str):
        """Permanently revoke the agent's authority."""
        self._state = ProtocolState.REVOKED
        self.audit.append("binding_revoked", self.agent_id, {"reason": reason})

    # ------------------------------------------------------------------
    # Kill switch
    # ------------------------------------------------------------------

    def engage_killswitch(self, reason: str):
        """Stop ALL actions immediately."""
        self._state = ProtocolState.FROZEN
        self.audit.append("killswitch_engaged", self.agent_id, {"reason": reason})
        self.audit.append("action_blocked", self.agent_id, {
            "request_id": "killswitch",
            "action_type": "KILL_SWITCH",
            "target": "SYSTEM",
            "reason": reason,
        })
        self.monitor.action_count += 1
        self.monitor.blocked_count += 1

    def disengage_killswitch(self):
        """Unfreeze. Does NOT restore revoked binding."""
        if self._state == ProtocolState.FROZEN:
            self._state = ProtocolState.ACTIVE
            self.audit.append("killswitch_disengaged", self.agent_id, {})

    # ------------------------------------------------------------------
    # Scope checking
    # ------------------------------------------------------------------

    def _check_scope(self, request: ActionRequest) -> str | None:
        """Returns None if within scope, or a reason string if blocked.

        DENY-BY-DEFAULT. The logic:

        1. Closed verb check — if the action_type isn't in the registered
           vocabulary, block it. This stops the model from inventing a new
           verb ("internal_transfer", "spawn_subagent_v2", "magic") that no
           rule covers. An unregistered verb is never allowed.

        2. For each rule whose action_type matches (or is None):
           a. forbidden_targets — if ANY matches, block. (Token/regex/glob,
              not raw substring, so "admin" blocks /api/admin but not
              readmymind.)
           b. allowed_targets — the action is permitted ONLY if it matches
              one of these by the rule's match kind. If the rule has
              allowed_targets and the target isn't in them, block.

        3. No rule explicitly permitted it → block. Scope is an allowlist,
           not a hope. The default outcome is DENY.
        """
        # 1. Closed verb vocabulary (deny-by-default at the verb level)
        if (self.allowed_action_types
                and request.action_type not in self.allowed_action_types):
            return (
                f"Action type '{request.action_type}' is not in the "
                f"registered action vocabulary {self.allowed_action_types} — "
                f"denied by default"
            )

        # Collect whether any rule explicitly permits this target.
        permitted = False
        # Track the tightest per-rule cost cap among rules that apply to
        # this action_type (used after permission is established).
        per_rule_caps: list[float] = []
        for rule in self.scope_rules:
            if rule.action_type is not None and request.action_type != rule.action_type:
                continue

            # forbidden first — hard deny, wins immediately
            if rule.forbidden_targets:
                for pattern in rule.forbidden_targets:
                    if target_matches(pattern, request.target, rule.forbid_match):
                        return (
                            f"Target '{request.target}' matches forbidden "
                            f"pattern '{pattern}' ({rule.forbid_match})"
                        )

            # allowed_targets is a precise allowlist for this rule
            if rule.allowed_targets is not None:
                if any(target_matches(p, request.target, rule.match)
                       for p in rule.allowed_targets):
                    # This rule permits the target. Now bind the OTHER
                    # dimensions of least-privilege — any one being broad
                    # makes the permission deceptive, so check them here.
                    if rule.methods is not None and request.method is not None:
                        if request.method.upper() not in [m.upper() for m in rule.methods]:
                            return (
                                f"Method {request.method} not permitted for "
                                f"'{request.target}' — allowed: {rule.methods}"
                            )
                    if request.method is None and rule.methods is not None:
                        return (
                            f"Action omits HTTP method; rule requires one of "
                            f"{rule.methods} for '{request.target}'"
                        )
                    if rule.param_schema is not None:
                        reason = validate_params(request.params, rule.param_schema)
                        if reason:
                            return (
                                f"Params violate scope rule for "
                                f"'{request.target}': {reason}"
                            )
                    if rule.max_cost is not None:
                        per_rule_caps.append(rule.max_cost)
                    permitted = True
                # If this rule carries an allowlist and the target hit none,
                # the rule does NOT permit it. We don't deny here because a
                # later rule could permit it — but if NO rule permits it,
                # the final default denies.
                continue

            # A rule with action_type match and no allowed_targets is a
            # blanket allowance for that verb (e.g. allow all "read_file").
            # Rare; explicit allowlists are preferred. Still bind method/params.
            if rule.methods is not None and request.method is not None:
                if request.method.upper() not in [m.upper() for m in rule.methods]:
                    return (
                        f"Method {request.method} not permitted for verb "
                        f"'{request.action_type}' — allowed: {rule.methods}"
                    )
            if rule.param_schema is not None:
                reason = validate_params(request.params, rule.param_schema)
                if reason:
                    return (
                        f"Params violate scope rule for '{request.action_type}': {reason}"
                    )
            if rule.max_cost is not None:
                per_rule_caps.append(rule.max_cost)
            permitted = True

        if not permitted:
            return (
                f"No scope rule permits action '{request.action_type}' on "
                f"target '{request.target}' — denied by default "
                f"(scope is an allowlist, not a blocklist)"
            )

        # Per-rule cost cap (tightest wins) — the real bound, independent
        # of the global budget (which only catches volume).
        if per_rule_caps:
            tightest = min(per_rule_caps)
            if request.estimated_cost > tightest:
                return (
                    f"Action cost ${request.estimated_cost:.2f} exceeds "
                    f"per-rule cap ${tightest:.2f}"
                )

        if request.action_type == "spawn_subagent" and not all(
            r.allow_subactions for r in self.scope_rules
            if r.action_type in (None, "spawn_subagent")
        ):
            return "Sub-agent spawning is disabled by scope rules"

        return None

    # ------------------------------------------------------------------
    # Budget checking
    # ------------------------------------------------------------------

    def _check_budget(self, request: ActionRequest) -> str | None:
        if self.budget_limit is None:
            return None
        projected = self._spent + request.estimated_cost
        if projected > self.budget_limit:
            return (
                f"Projected spend ${projected:.2f} exceeds budget limit "
                f"${self.budget_limit:.2f}"
            )
        return None

    # ------------------------------------------------------------------
    # Approval gates
    # ------------------------------------------------------------------

    def _needs_approval(self, request: ActionRequest) -> bool:
        """Does this action require human approval before execution?"""
        for rule in self.scope_rules:
            if rule.action_type == request.action_type and rule.requires_approval:
                return True

        if request.estimated_cost >= self.approval_threshold_cost:
            return True

        if request.urgency == "critical":
            return True

        return False

    def request_approval(self, request: ActionRequest) -> str:
        """Submit an action for human approval. Returns approval token."""
        token = uuid.uuid4().hex[:12]
        self._pending_approvals[token] = request
        self.audit.append("approval_requested", self.agent_id, {
            "token": token,
            "request_id": request.request_id,
            "action_type": request.action_type,
            "target": request.target,
            "estimated_cost": request.estimated_cost,
            "urgency": request.urgency,
        })
        return token

    def decide_approval(
        self,
        token: str,
        approved: bool,
        approver: str,
        reason: str | None = None,
    ) -> bool:
        """Human approves or denies an action. Returns True if approved."""
        if token not in self._pending_approvals:
            return False

        request = self._pending_approvals.pop(token)
        self.audit.append("approval_decision", self.agent_id, {
            "token": token,
            "request_id": request.request_id,
            "approved": approved,
            "approver": approver,
            "reason": reason,
        })

        result = ActionResult(
            request.request_id,
            ActionOutcome.ALLOWED if approved else ActionOutcome.BLOCKED_SCOPE,
            block_reason=f"Denied by {approver}: {reason or 'no reason given'}"
            if not approved
            else None,
            executed=approved,
        )
        self.monitor.record_action(result, request)

        if approved and self.budget_limit is not None:
            self._spent += request.estimated_cost

        if approved:
            # Whiten this exact intent for a short window so the agent's
            # retry (same target + cost) is allowed to proceed.
            key = (request.target, int(round(request.estimated_cost * 100)))
            self._approved_intents[key] = time.time() + 300  # 5-minute window

        return approved

    def get_pending_approvals(self) -> list[dict]:
        """What's waiting for human decision?"""
        return [{
            "token": token,
            "request_id": req.request_id,
            "action_type": req.action_type,
            "target": req.target,
            "estimated_cost": req.estimated_cost,
            "urgency": req.urgency,
        } for token, req in self._pending_approvals.items()]

    # ------------------------------------------------------------------
    # The main gate — single entry point for all agent actions
    # ------------------------------------------------------------------

    def execute(self, request: ActionRequest) -> ActionResult:
        """
        The single entry point for all agent actions.

        This is the enforcement layer. The agent calls this. The protocol
        decides. Nothing bypasses this.

        Execution order:
        1. Binding check — is the agent still authorized?
        2. Kill switch check — is the protocol frozen?
        3. Scope check — is this action within allowed scope?
        4. Budget check — will this exceed the budget?
        5. Approval gate — does this need human sign-off?
        6. Allow and execute — all checks passed.
        """
        # 1. Binding check
        if not self.verify_binding():
            return ActionResult(
                request.request_id,
                ActionOutcome.BLOCKED_SCOPE,
                block_reason="Agent binding revoked — no actions permitted",
            )

        # 2. Kill switch check
        if self._state == ProtocolState.FROZEN:
            return ActionResult(
                request.request_id,
                ActionOutcome.BLOCKED_KILLSWITCH,
                block_reason="Protocol frozen by kill switch — all actions blocked",
            )

        # 3. Scope check
        scope_violation = self._check_scope(request)
        if scope_violation:
            return ActionResult(
                request.request_id,
                ActionOutcome.BLOCKED_SCOPE,
                block_reason=scope_violation,
            )

        # 4. Budget check
        budget_violation = self._check_budget(request)
        if budget_violation:
            return ActionResult(
                request.request_id,
                ActionOutcome.BLOCKED_BUDGET,
                block_reason=budget_violation,
            )

        # 5. Approval gate
        if self._needs_approval(request):
            # If a human already approved this exact intent recently, honor it.
            key = (request.target, int(round(request.estimated_cost * 100)))
            expiry = self._approved_intents.get(key)
            if expiry and time.time() < expiry:
                # Approved — fall through to execute.
                pass
            else:
                token = self.request_approval(request)
                result = ActionResult(
                    request.request_id,
                    ActionOutcome.PENDING_APPROVAL,
                    requires_approval_for=token,
                )
                self.monitor.record_action(result, request)
                return result

        # 6. All checks passed — ALLOW and execute
        self._spent += request.estimated_cost
        result = ActionResult(request.request_id, ActionOutcome.ALLOWED, executed=True)

        self.monitor.record_action(result, request)
        self.audit.append("action_executed", self.agent_id, {
            "request_id": request.request_id,
            "action_type": request.action_type,
            "target": request.target,
            "params": request.params,
            "cost": request.estimated_cost,
            "urgency": request.urgency,
        })

        return result


class BoundAgent:
    """
    An agent that is unambiguously tied to a user.

    The agent doesn't have its own authority. It operates through the
    SafetyProtocol which enforces binding, scope, budget, approval, and
    kill switch. Every action the agent takes is attributable to the user.
    """

    def __init__(
        self,
        agent_id: str,
        user_id: str,
        safety_protocol: SafetyProtocol,
    ):
        self.agent_id = agent_id
        self.user_id = user_id
        self.protocol = safety_protocol
        self.persona: dict = {}

    def set_persona(self, name: str, role: str, capabilities: list[str]):
        """Set the agent's persona — what it is and what it can do."""
        self.persona = {
            "name": name,
            "role": role,
            "capabilities": capabilities,
            "bound_to": self.user_id,
        }
        self.protocol.audit.append("agent_persona_set", self.agent_id, self.persona)

    def propose_action(
        self,
        action_type: str,
        target: str,
        params: dict | None = None,
        estimated_cost: float = 0.0,
        urgency: str = "normal",
    ) -> ActionResult:
        """
        The agent proposes an action. The safety protocol decides.

        The agent cannot execute anything without going through the protocol.

        Args:
            action_type: Type of action (e.g., "api_call", "spend", "write_file")
            target: What the action is acting on
            params: Additional parameters for the action
            estimated_cost: Estimated cost of the action
            urgency: Urgency level ("low", "normal", "high", "critical")

        Returns:
            ActionResult with the outcome and any block reasons
        """
        request = ActionRequest(
            action_type=action_type,
            target=target,
            params=params or {},
            estimated_cost=estimated_cost,
            urgency=urgency,
        )
        return self.protocol.execute(request)

    def get_status(self) -> dict:
        """Get comprehensive agent status."""
        return {
            "agent_id": self.agent_id,
            "user_id": self.user_id,
            "protocol_state": self.protocol._state.value,
            "binding": self.protocol.binding,
            "monitor": self.protocol.monitor.get_status(),
            "pending_approvals": self.protocol.get_pending_approvals(),
        }
