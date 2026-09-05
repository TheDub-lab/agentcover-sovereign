"""
Scope rule linter — catch broad rules BEFORE they ship.

The whole point of the framework is that vague scope makes every other
control decorative. This module statically inspects a set of ScopeRules
(and the action vocabulary they sit inside) and reports the ways a rule
is broader than least-privilege. It does NOT run the protocol — it reads
the rules you wrote and tells you where the perimeter is soft.

Severity levels:
  ERROR   — the rule almost certainly permits more than intended
  WARN    — the rule is permissive in a way that's easy to miss
  INFO    — structural note (dead verb, blanket allow)

Run it in CI or in a pre-deploy check. A single ERROR or WARN should
block the deploy until the rule is tightened.

Usage:
    from safety_protocol.scope_linter import lint_rules, Severity
    findings = lint_rules(rules, allowed_action_types)
    if any(f.severity in (Severity.ERROR, Severity.WARN) for f in findings):
        raise SystemExit("scope too broad to ship")
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable

from .core import ScopeRule


class Severity(str, Enum):
    ERROR = "ERROR"
    WARN = "WARN"
    INFO = "INFO"


@dataclass
class Finding:
    severity: Severity
    code: str
    message: str
    rule_index: int | None = None
    action_type: str | None = None

    def __str__(self) -> str:
        loc = f"[rule {self.rule_index}]" if self.rule_index is not None else ""
        at = f" ({self.action_type})" if self.action_type else ""
        return f"{self.severity.value}{loc}{at} {self.code}: {self.message}"


# Tokens that, on their own, indicate a coarse allowlist. A rule that
# permits the bare token with no further path is effectively "allow this
# whole origin / whole verb class".
_BROAD_TARGET_HINTS = (
    "*",
    "/*",
    "/v1/",
    "/v1/*",
    "/api/",
    "/api/*",
    "/",
)


def _is_catch_all_prefix(rule: ScopeRule) -> bool:
    """A prefix match on a root-ish or wildcardy target = catch-all."""
    if rule.match != "prefix":
        return False
    for t in (rule.allowed_targets or []):
        lt = t.lower().rstrip("/")
        # wildcard anywhere -> catch-all
        if "*" in t:
            return True
        # a bare scheme://host or scheme://host/ with nothing after
        if lt.count("/") <= 3:
            # e.g. https://api.x.com  (no /v1/search after it)
            return True
    return False


def _contradiction(rule: ScopeRule) -> bool:
    """Same token appears in both allowed and forbidden lists."""
    if not rule.allowed_targets or not rule.forbidden_targets:
        return False
    a = {t.lower() for t in rule.allowed_targets}
    f = {t.lower() for t in rule.forbidden_targets}
    return bool(a & f)


def lint_rules(
    rules: Iterable[ScopeRule],
    allowed_action_types: list[str] | None = None,
) -> list[Finding]:
    """Lint a scope ruleset. Returns a list of Findings (empty = clean)."""
    rules = list(rules)
    findings: list[Finding] = []

    covered_verbs: set[str] = set()
    for i, rule in enumerate(rules):
        at = rule.action_type
        if at is not None:
            covered_verbs.add(at)

            # 1. Catch-all prefix -> ERROR
            if _is_catch_all_prefix(rule):
                findings.append(Finding(
                    Severity.ERROR, "CATCH_ALL_PREFIX",
                    f"prefix match on broad target(s) {rule.allowed_targets} "
                    f"permits everything under it (/admin, /delete, …). "
                    f"Use match='exact' or a narrow path, and bind method+params.",
                    rule_index=i, action_type=at,
                ))

            # 2. Missing method on a concrete target -> WARN
            if rule.allowed_targets is not None and rule.methods is None:
                findings.append(Finding(
                    Severity.WARN, "NO_METHOD",
                    f"rule allows the action regardless of HTTP/transport verb. "
                    f"A read rule that also permits DELETE is not least-privilege. "
                    f"Bind `methods=[...]`.",
                    rule_index=i, action_type=at,
                ))

            # 3. Missing param_schema on a concrete target -> WARN
            if rule.allowed_targets is not None and rule.param_schema is None:
                findings.append(Finding(
                    Severity.WARN, "NO_PARAM_SCHEMA",
                    f"rule allows the target for ANY params. Params are how a "
                    f"'safe' endpoint does unsafe things (?confirm=true). Bind "
                    f"`param_schema` (required keys, enums, ranges).",
                    rule_index=i, action_type=at,
                ))

            # 4. No per-rule cap -> WARN (for any action that can cost money)
            if rule.max_cost is None and at in ("spend", "payment", "api_call"):
                findings.append(Finding(
                    Severity.WARN, "NO_PER_RULE_CAP",
                    f"rule has no per-action max_cost. The global budget only "
                    f"catches volume, not a single oversized action. Add `max_cost`.",
                    rule_index=i, action_type=at,
                ))

            # 5. Blanket rule (no allowlist) -> WARN
            if rule.allowed_targets is None:
                findings.append(Finding(
                    Severity.WARN, "BLANKET_ALLOW",
                    f"rule has action_type but no allowed_targets — it permits "
                    f"EVERY target for verb '{at}'. Prefer an explicit allowlist.",
                    rule_index=i, action_type=at,
                ))

        # 6. Contradiction within the rule -> ERROR
        if _contradiction(rule):
            findings.append(Finding(
                Severity.ERROR, "ALLOW_FORBID_CONFLICT",
                f"same token appears in both allowed_targets and "
                f"forbidden_targets — the rule is self-contradictory.",
                rule_index=i, action_type=at,
            ))

    # 7. Dead verbs: in vocabulary but no rule covers them -> INFO
    if allowed_action_types:
        for verb in allowed_action_types:
            if verb not in covered_verbs:
                findings.append(Finding(
                    Severity.INFO, "DEAD_VERB",
                    f"action type '{verb}' is in the vocabulary but no scope "
                    f"rule permits it — every such action is denied by default "
                    f"(often intentional; noted for awareness).",
                    action_type=verb,
                ))

    return findings


def lint_report(findings: list[Finding]) -> str:
    """Human-readable report. Empty findings -> a clean banner."""
    if not findings:
        return "SCOPE LINT: clean — no broad or contradictory rules found."
    lines = ["SCOPE LINT FINDINGS", "=" * 60]
    for f in findings:
        lines.append(str(f))
    n_err = sum(1 for f in findings if f.severity == Severity.ERROR)
    n_warn = sum(1 for f in findings if f.severity == Severity.WARN)
    lines.append("=" * 60)
    lines.append(f"{n_err} ERROR(s), {n_warn} WARN(s) — "
                 f"{'BLOCK' if (n_err or n_warn) else 'ok to ship'}")
    return "\n".join(lines)
