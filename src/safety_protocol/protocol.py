# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Michael / TheDub-lab
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

import contextlib
import time
import uuid

from .core import (
    ActionOutcome,
    ActionRequest,
    ActionResult,
    AuditTrail,
    Monitor,
    ProtocolState,
    ScopeRule,
    target_matches,
    validate_params,
)
from .shipping import params_digest


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
        mode: str = "enforce",
        decision_sinks: list | None = None,
        approval_ttl_s: float = 300.0,
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
            approval_ttl_s: How long an approval token stays valid, and how
                long an approved intent stays "whitened" for the retry, in
                seconds. Bounds the window in which a leaked token can be
                replayed.
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
        # Per-token metadata: created_at / expires_at / digest / channel /
        # session_id. Kept alongside the pending request so a token can be
        # expired, bound to the exact intent, and attributed to a channel.
        self._approval_meta: dict[str, dict] = {}
        self.approval_ttl_s = float(approval_ttl_s)

        # "enforce" (default) blocks per policy. "shadow" logs what the
        # policy WOULD have done (policy_decision) but returns allowed for
        # everything policy denied — a safe rollout mode. The kill switch
        # and a revoked binding still block in shadow mode.
        if mode not in ("enforce", "shadow"):
            raise ValueError(f"mode must be 'enforce' or 'shadow', got {mode!r}")
        self.mode = mode

        # Decision sinks: callables notified (request, result, decision) after
        # every decision. Used to ship audit entries to an external receiver.
        # Sink failures are swallowed — logging must never break enforcement.
        self.decision_sinks: list = list(decision_sinks or [])
        # Best-effort id of the scope rule that produced the last decision.
        self._matched_rule_id: str | None = None
        # Approved intents: (target, cost-cents, intent-digest) -> expiry ts.
        # When a human approves an action, the matching retry is allowed for a
        # short window so the agent can actually proceed after sign-off.
        # Per-intent, not a blanket allow — a different target, cost, or set of
        # params still needs approval (the digest covers action_type + target +
        # params, so an approved call cannot be swapped for a different one).
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
    # Decision sinks (log shipping)
    # ------------------------------------------------------------------

    def add_decision_sink(self, sink) -> None:
        """Register a callable notified as ``sink(request, result, decision)``
        after every decision. ``decision`` is an override string for approval
        outcomes (``"approved"`` / ``"rejected"``), else ``None`` so the sink
        derives it from the result. Sink errors are swallowed.
        """
        self.decision_sinks.append(sink)

    def _announce(self, request, result, decision=None) -> None:
        result.execution_log.setdefault("rule_id", self._matched_rule_id)
        sink_decision = decision
        for sink in self.decision_sinks:
            with contextlib.suppress(Exception):
                sink(request, result, sink_decision)

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
        # Ship the kill-switch event itself (it never flows through execute()).
        req = ActionRequest(
            action_type="killswitch", target="SYSTEM", urgency="critical")
        res = ActionResult(
            req.request_id, ActionOutcome.BLOCKED_KILLSWITCH,
            block_reason=reason)
        res.execution_log["policy_outcome"] = ActionOutcome.BLOCKED_KILLSWITCH.value
        self._announce(req, res, decision="killswitch")

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
        # Best-effort: record the rule that produced this decision (for logs).
        self._matched_rule_id = None

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
                        self._matched_rule_id = rule.rule_id
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
                    if (rule.methods is not None and request.method is not None
                            and request.method.upper() not in [m.upper() for m in rule.methods]):
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
                    self._matched_rule_id = rule.rule_id
                # If this rule carries an allowlist and the target hit none,
                # the rule does NOT permit it. We don't deny here because a
                # later rule could permit it — but if NO rule permits it,
                # the final default denies.
                continue

            # A rule with action_type match and no allowed_targets is a
            # blanket allowance for that verb (e.g. allow all "read_file").
            # Rare; explicit allowlists are preferred. Still bind method/params.
            if (rule.methods is not None and request.method is not None
                    and request.method.upper() not in [m.upper() for m in rule.methods]):
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
            self._matched_rule_id = rule.rule_id

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
        """Does this action require human approval before execution?

        Approval is a property of the rule that actually *covers* the target —
        not of the action_type as a whole. Two rules can share an action_type
        (e.g. an MCP ``read_file`` rule and an MCP ``write_file`` rule); if only
        the write rule sets ``requires_approval``, a read must not be held.
        """
        for rule in self.scope_rules:
            if rule.action_type not in (None, request.action_type):
                continue
            # Only a rule that permits this target can require approval for it.
            if rule.allowed_targets is not None and not any(
                target_matches(p, request.target, rule.match)
                for p in rule.allowed_targets
            ):
                continue
            if rule.requires_approval:
                return True

        if request.estimated_cost >= self.approval_threshold_cost:
            return True

        return request.urgency == "critical"

    def _approval_digest(self, request: ActionRequest) -> str:
        """Digest binding an approval to the exact intent that was requested.

        Covers action_type + target + params. An approval for one intent can
        never whiten a different one (different verb, target, or params all
        change the digest).
        """
        return params_digest({
            "action_type": request.action_type,
            "target": request.target,
            "params": request.params,
        })

    def request_approval(
        self,
        request: ActionRequest,
        *,
        channel: str | None = None,
        session_id: str | None = None,
        ttl_s: float | None = None,
    ) -> str:
        """Submit an action for human approval. Returns approval token.

        The token is a short reference id, single-use, and expires after
        ``approval_ttl_s`` (or ``ttl_s``). ``channel`` records where the
        approval is expected to arrive (``"control"``, ``"cli"``, ``"telegram"``
        …) and ``session_id`` lets a caller reject approval replayed on the
        same session that made the request.
        """
        token = uuid.uuid4().hex[:12]
        ttl = self.approval_ttl_s if ttl_s is None else float(ttl_s)
        now = time.time()
        self._pending_approvals[token] = request
        self._approval_meta[token] = {
            "created_at": now,
            "expires_at": now + ttl,
            "digest": self._approval_digest(request),
            "channel": channel,
            "session_id": session_id,
        }
        self.audit.append("approval_requested", self.agent_id, {
            "token": token,
            "request_id": request.request_id,
            "action_type": request.action_type,
            "target": request.target,
            "estimated_cost": request.estimated_cost,
            "urgency": request.urgency,
            "digest": self._approval_meta[token]["digest"],
            "channel": channel,
            "expires_at": self._approval_meta[token]["expires_at"],
        })
        return token

    def _reject_approval(
        self,
        token: str,
        request: ActionRequest,
        reason: str,
        *,
        approver: str,
        channel: str | None,
        code: str,
    ) -> bool:
        """Drop a pending approval and record the rejection, hash-chained."""
        self._pending_approvals.pop(token, None)
        self._approval_meta.pop(token, None)
        self.audit.append("approval_rejected", self.agent_id, {
            "token": token,
            "request_id": request.request_id,
            "reason": reason,
            "code": code,
            "approver": approver,
            "channel": channel,
        })
        result = ActionResult(
            request.request_id,
            ActionOutcome.BLOCKED_SCOPE,
            block_reason=f"Approval rejected: {reason}",
        )
        result.execution_log["approver"] = approver
        if channel is not None:
            result.execution_log["approval_channel"] = channel
        self.monitor.record_action(result, request)
        self._announce(request, result, decision="rejected")
        return False

    def decide_approval(
        self,
        token: str,
        approved: bool,
        approver: str,
        reason: str | None = None,
        *,
        channel: str | None = None,
        session_id: str | None = None,
    ) -> bool:
        """Human approves or denies an action. Returns True if approved.

        Hardened: the token is single-use and expires; the approver cannot be
        the agent itself; and an approval arriving on the same ``session_id``
        as the request is refused. ``channel`` records where the decision came
        from, and both ``approver`` and ``channel`` land in the hash chain.
        """
        if token not in self._pending_approvals:
            self.audit.append("approval_unknown_token", self.agent_id, {
                "token": token,
                "approver": approver,
                "channel": channel,
            })
            return False

        request = self._pending_approvals[token]
        meta = self._approval_meta.get(token, {})

        # An agent must not approve its own action — that is not a human in
        # the loop, it is the agent talking to itself.
        if approver and approver == self.agent_id:
            return self._reject_approval(
                token, request, "approver is the agent itself (self-approval)",
                approver=approver, channel=channel, code="self_approval")

        # Expiry — a stale token cannot be replayed later.
        expires_at = meta.get("expires_at")
        if expires_at is not None and time.time() >= expires_at:
            return self._reject_approval(
                token, request, "approval token expired",
                approver=approver, channel=channel, code="expired")

        # Same-session replay — the request and its approval must come from
        # different sessions/channels when a session id is supplied.
        if (session_id is not None and meta.get("session_id") is not None
                and session_id == meta["session_id"]):
            return self._reject_approval(
                token, request, "approval arrived on the request session",
                approver=approver, channel=channel, code="same_session")

        digest = meta.get("digest") or self._approval_digest(request)
        self._pending_approvals.pop(token, None)
        self._approval_meta.pop(token, None)
        self.audit.append("approval_decision", self.agent_id, {
            "token": token,
            "request_id": request.request_id,
            "approved": approved,
            "approver": approver,
            "reason": reason,
            "channel": channel,
            "digest": digest,
        })

        result = ActionResult(
            request.request_id,
            ActionOutcome.ALLOWED if approved else ActionOutcome.BLOCKED_SCOPE,
            block_reason=f"Denied by {approver}: {reason or 'no reason given'}"
            if not approved
            else None,
            executed=approved,
        )
        result.execution_log["approver"] = approver
        if channel is not None:
            result.execution_log["approval_channel"] = channel
        self.monitor.record_action(result, request)

        if approved and self.budget_limit is not None:
            self._spent += request.estimated_cost

        if approved:
            # Whiten this exact intent for a short window so the agent's
            # retry (same target + cost + params) is allowed to proceed.
            key = (request.target, int(round(request.estimated_cost * 100)), digest)
            self._approved_intents[key] = time.time() + self.approval_ttl_s

        self._announce(request, result, decision="approved" if approved else "rejected")
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
            "channel": self._approval_meta.get(token, {}).get("channel"),
            "expires_at": self._approval_meta.get(token, {}).get("expires_at"),
        } for token, req in self._pending_approvals.items()]

    # ------------------------------------------------------------------
    # The main gate — single entry point for all agent actions
    # ------------------------------------------------------------------

    def _evaluate(self, request: ActionRequest) -> ActionResult:
        """Pure policy evaluation — what SHOULD happen, before shadow mode.

        Order:
        1. Binding check — is the agent still authorized?
        2. Kill switch check — is the protocol frozen?
        3. Scope check — is this action within allowed scope?
        4. Budget check — will this exceed the budget?
        5. Approval gate — does this need human sign-off?
        6. Allow.
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
            # The digest makes the approval specific to this action_type +
            # target + params, so a retry with different params is not allowed.
            key = (request.target, int(round(request.estimated_cost * 100)),
                   self._approval_digest(request))
            expiry = self._approved_intents.get(key)
            if not (expiry and time.time() < expiry):
                # In shadow mode we do not create a real pending approval; the
                # policy outcome is still "needs_approval" and gets logged.
                token = None
                if self.mode != "shadow":
                    token = self.request_approval(request)
                return ActionResult(
                    request.request_id,
                    ActionOutcome.PENDING_APPROVAL,
                    requires_approval_for=token,
                )

        # 6. All checks passed.
        return ActionResult(request.request_id, ActionOutcome.ALLOWED, executed=True)

    def execute(self, request: ActionRequest) -> ActionResult:
        """
        The single entry point for all agent actions.

        This is the enforcement layer. The agent calls this. The protocol
        decides. Nothing bypasses this.

        Runs the policy (``_evaluate``), applies the mode, records the
        outcome once, and notifies any decision sinks (log shipping).
        """
        policy = self._evaluate(request)
        policy_value = policy.outcome.value
        result = policy

        shadowed = (
            self.mode == "shadow"
            and policy.outcome in (
                ActionOutcome.BLOCKED_SCOPE,
                ActionOutcome.BLOCKED_BUDGET,
                ActionOutcome.PENDING_APPROVAL,
            )
        )
        if shadowed:
            # Shadow mode: log what policy said, but allow the action through.
            result = ActionResult(
                request.request_id,
                ActionOutcome.ALLOWED,
                executed=True,
                execution_log={
                    "shadow": True,
                    "policy_outcome": policy_value,
                    "policy_reason": policy.block_reason,
                },
            )

        result.execution_log.setdefault("policy_outcome", policy_value)

        if result.outcome == ActionOutcome.ALLOWED and result.executed:
            self._spent += request.estimated_cost

        self.monitor.record_action(result, request)

        if result.outcome == ActionOutcome.ALLOWED and result.executed:
            self.audit.append("action_executed", self.agent_id, {
                "request_id": request.request_id,
                "action_type": request.action_type,
                "target": request.target,
                "params": request.params,
                "cost": request.estimated_cost,
                "urgency": request.urgency,
            })

        self._announce(request, result)
        return result

    def block(
        self,
        request: ActionRequest,
        reason: str,
        outcome: ActionOutcome = ActionOutcome.BLOCKED_SCOPE,
    ) -> ActionResult:
        """Record a denial that never reached policy evaluation.

        Used by adapters (e.g. the MCP proxy) to reject malformed input — a
        resource URI that fails normalization — in every mode, including
        shadow. Shadow mode answers policy *questions*; malformed input is
        never forwarded to the upstream.
        """
        result = ActionResult(request.request_id, outcome, block_reason=reason)
        result.execution_log["policy_outcome"] = outcome.value
        result.execution_log["policy_reason"] = reason
        self.monitor.record_action(result, request)
        self._announce(request, result)
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
