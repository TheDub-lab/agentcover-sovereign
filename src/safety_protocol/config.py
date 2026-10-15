# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Michael / TheDub-lab
"""
User-config -> SafetyProtocol builder (part of the free MIT SDK).

This reads a user-controlled guard config, builds the scope rules, LINTS
them, and fails closed on broad/self-contradictory rules. It is the local
(enforcement-only) path used by ``safety-guard check`` and ``safety-guard
lint`` and by the BSL ``GuardService`` platform layer.

Keeping this in the MIT SDK is deliberate: the ability to run *one* guard
locally is free. The hosted service, audit/evidence stack, and on-chain
integration live in the BSL platform layer.
"""
from __future__ import annotations

from .core import AuditTrail, ScopeRule
from .protocol import SafetyProtocol
from .scope_linter import Severity, lint_report, lint_rules


def load_rules(cfg: dict) -> list[ScopeRule]:
    raw = cfg.get("scope_rules", [])
    rules = []
    for r in raw:
        rules.append(ScopeRule(
            action_type=r.get("action_type"),
            allowed_targets=r.get("allowed_targets"),
            forbidden_targets=r.get("forbidden_targets"),
            match=r.get("match", "exact"),
            forbid_match=r.get("forbid_match", "token"),
            methods=r.get("methods"),
            param_schema=r.get("param_schema"),
            max_cost=r.get("max_cost"),
            requires_approval=bool(r.get("requires_approval", False)),
            allow_subactions=bool(r.get("allow_subactions", True)),
            rule_id=r.get("id"),
        ))
    return rules


def build_protocol_from_config(cfg: dict) -> tuple[SafetyProtocol, list]:
    """Build the protocol from a user config. LINTS first, fails closed.

    Returns (protocol, findings). Raises SystemExit if the config is too
    broad to ship — the guard must not start with dangerous rules.
    """
    vocab = cfg.get("allowed_action_types", [])
    rules = load_rules(cfg)
    findings = lint_rules(rules, vocab)
    blocking = [f for f in findings
                if f.severity in (Severity.ERROR, Severity.WARN)]
    if blocking:
        # Fail closed: refuse to run with a broad/self-contradictory ruleset.
        raise SystemExit(
            "REFUSING TO START — scope rules failed lint:\n"
            + lint_report(findings)
        )
    audit = AuditTrail()
    protocol = SafetyProtocol(
        agent_id=cfg.get("agent_id", "guard-agent"),
        user_id=cfg.get("user_id", "user"),
        scope_rules=rules,
        budget_limit=cfg.get("budget_limit"),
        approval_threshold_cost=cfg.get("approval_threshold_cost", 10.0),
        audit=audit,
        allowed_action_types=vocab,
        mode=cfg.get("mode", "enforce"),
    )
    return protocol, findings
