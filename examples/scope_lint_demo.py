#!/usr/bin/env python3
"""
Scope linter demo — prove the linter catches broad rules before they ship.

Shows the contrast that matters:
  - the OLD lazy rule (catch-all prefix, no method/params/cap) -> ERROR/WARN
  - the NEW tight rule (exact target, method, param_schema, cap) -> clean

Run:  python examples/scope_lint_demo.py
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from safety_protocol.core import ScopeRule
from safety_protocol.scope_linter import lint_rules, lint_report, Severity

VOCAB = ["api_call", "spend", "send_message", "payment"]

# ── The OLD, lazy rule we used to write ──
old_rule = ScopeRule(
    action_type="api_call",
    allowed_targets=["https://api.research.example/v1/"],   # catch-all prefix
    match="prefix",                                          # no method, no params, no cap
)

# ── The NEW, least-privilege rule ──
new_rule = ScopeRule(
    action_type="api_call",
    allowed_targets=["https://api.research.example/v1/search"],
    match="exact",
    methods=["POST"],
    param_schema={
        "required": ["query"],
        "properties": {"query": {"type": "string", "maximum": 200}},
        "additional_properties": False,
    },
    max_cost=5.0,
)

print("=" * 70)
print("LINTING THE OLD (BROAD) RULE")
print("=" * 70)
old_findings = lint_rules([old_rule], VOCAB)
print(lint_report(old_findings))

print()
print("=" * 70)
print("LINTING THE NEW (TIGHT) RULE")
print("=" * 70)
new_findings = lint_rules([new_rule], VOCAB)
print(lint_report(new_findings))

print()
print("=" * 70)
print("ASSERTIONS")
print("=" * 70)
ok = True

# Old rule must trip ERROR (catch-all prefix) + WARN x3
old_err = [f for f in old_findings if f.severity == Severity.ERROR]
old_warn = [f for f in old_findings if f.severity == Severity.WARN]
c1 = any(f.code == "CATCH_ALL_PREFIX" for f in old_err)
c2 = any(f.code == "NO_METHOD" for f in old_warn)
c3 = any(f.code == "NO_PARAM_SCHEMA" for f in old_warn)
c4 = any(f.code == "NO_PER_RULE_CAP" for f in old_warn)
if c1 and c2 and c3 and c4:
    print("  PASS  broad rule flagged: CATCH_ALL_PREFIX + NO_METHOD + "
          "NO_PARAM_SCHEMA + NO_PER_RULE_CAP")
else:
    ok = False
    print("  FAIL  broad rule not fully flagged "
          f"(err={[f.code for f in old_err]}, warn={[f.code for f in old_warn]})")

# New rule must be clean (no ERROR, no WARN)
new_block = [f for f in new_findings
             if f.severity in (Severity.ERROR, Severity.WARN)]
if not new_block:
    print("  PASS  tight rule is clean (no ERROR/WARN)")
else:
    ok = False
    print(f"  FAIL  tight rule flagged: {[f.code for f in new_block]}")

# A deploy gate: ERRORS/WARNINGS must block
would_block = any(f.severity in (Severity.ERROR, Severity.WARN)
                  for f in old_findings)
if would_block:
    print("  PASS  deploy gate would BLOCK the broad ruleset")
else:
    ok = False
    print("  FAIL  deploy gate did not block broad ruleset")

print()
print("RESULT:", "ALL PASS" if ok else "FAILURES PRESENT")
sys.exit(0 if ok else 1)
