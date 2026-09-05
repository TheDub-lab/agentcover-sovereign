#!/usr/bin/env python3
"""
Safe spend demo — the product, end-to-end.

An agent that pays via x402, gated by the SafetyProtocol:
  - recipient allow/deny (token match)
  - per-payment cap
  - rolling budget
  - approval threshold
  - kill switch

Run the mock merchant in another terminal first:
  python examples/mock_merchant.py

Then:
  python examples/safe_spend_demo.py
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from safety_protocol import SafetyProtocol, ScopeRule, AuditTrail
from safety_protocol.payments import SafeSpendAgent, SimWallet

TRUSTED_MERCHANT = "0xMerchant1111111111111111111111111111111111"
EVIL_MERCHANT = "0xEvil9999999999999999999999999999999999"
MERCHANT_URL = "http://127.0.0.1:4020/weather"


def build_protocol() -> SafetyProtocol:
    audit = AuditTrail()
    protocol = SafetyProtocol(
        agent_id="spend-agent-01",
        user_id="alice",  # the accountable human this agent is bound to
        scope_rules=[
            ScopeRule(
                action_type="payment",
                allowed_targets=[TRUSTED_MERCHANT],
                match="exact",
                methods=["x402"],                  # only the x402 payment rail
                param_schema={
                    "required": ["resource"],
                    "properties": {
                        "resource": {"type": "string", "enum": ["weather"]},
                        "memo": {"type": "string", "maximum": 280},
                    },
                    "additional_properties": False,
                },
                forbidden_targets=["evil", "scam", "rug"],
                forbid_match="token",
                max_cost=1.00,           # per-payment cap: $1.00
            ),
        ],
        budget_limit=5.00,                # rolling spend cap
        approval_threshold_cost=0.50,     # anything over $0.50 needs approval
        audit=audit,
        allowed_action_types=["payment"],
    )
    return protocol


def banner(title: str):
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


def main():
    protocol = build_protocol()
    wallet = SimWallet(secret="demo-secret-do-not-use-in-production")
    agent = SafeSpendAgent(
        protocol=protocol,
        wallet=wallet,
        facilitator="https://x402.org/facilitator",  # production swap
    )

    # --- Case 1: normal allowed payment (under cap, under approval threshold)
    banner("CASE 1 — Normal allowed payment ($0.10 to trusted merchant)")
    r = agent.pay(MERCHANT_URL, recipient=TRUSTED_MERCHANT)
    print(f"  outcome:    {r.outcome}")
    print(f"  reason:     {r.reason}")
    print(f"  status:     {r.status_code}")
    if r.envelope:
        print(f"  signed:     from={r.envelope.from_addr[:10]}... to={r.envelope.to_addr[:10]}...")
        print(f"  amount:     {r.envelope.value/1_000_000:.2f} USDC")

    # --- Case 2: forbidden recipient — denied by default (not in allowlist)
    # Note: token-match 'evil' doesn't split hex addresses (single token); block
    # comes from deny-by-default on the allowlist, which is the correct control.
    banner("CASE 2 — Forbidden recipient (not in allowlist) — BLOCKED")
    r = agent.direct_pay(EVIL_MERCHANT, 0.10)
    print(f"  outcome:    {r.outcome}")
    print(f"  reason:     {r.reason}")
    print(f"  signed?     {'YES (BAD)' if r.envelope else 'no (correct)'}")

    # --- Case 3: over per-payment cap — blocked by scope
    banner("CASE 3 — Over per-payment cap ($50 > $1 cap) — should be BLOCKED")
    r = agent.direct_pay(TRUSTED_MERCHANT, 50.0)
    print(f"  outcome:    {r.outcome}")
    print(f"  reason:     {r.reason}")
    print(f"  signed?     {'YES (BAD)' if r.envelope else 'no (correct)'}")

    # --- Case 4: over approval threshold — pending human approval
    banner("CASE 4 — Over approval threshold ($0.75 > $0.50) — PENDING_APPROVAL")
    r = agent.direct_pay(TRUSTED_MERCHANT, 0.75)
    print(f"  outcome:    {r.outcome}")
    print(f"  approval_token: {r.approval_token}")
    # Human approves:
    if r.approval_token:
        ok = protocol.decide_approval(r.approval_token, approved=True, approver="alice")
        print(f"  human approved? {ok}")
        # Now re-run the payment (simulating the agent retrying post-approval)
        r2 = agent.direct_pay(TRUSTED_MERCHANT, 0.75)
        print(f"  post-approval outcome: {r2.outcome}")

    # --- Case 6: param binding violation (wrong resource) — blocked
    banner("CASE 6 — Param violation (resource='stock_tip' not in enum) — BLOCKED")
    r = agent.direct_pay(TRUSTED_MERCHANT, 0.10, resource="stock_tip")
    print(f"  outcome:    {r.outcome}")
    print(f"  reason:     {r.reason}")
    print(f"  signed?     {'YES (BAD)' if r.envelope else 'no (correct)'}")

    # --- Case 7: kill switch — nothing pays after
    banner("CASE 7 — Kill switch engaged — all payments BLOCKED")
    protocol.engage_killswitch("User froze the agent")
    r = agent.pay(MERCHANT_URL, recipient=TRUSTED_MERCHANT)
    print(f"  outcome:    {r.outcome}")
    print(f"  reason:     {r.reason}")

    # --- Audit trail
    banner("AUDIT TRAIL (every decision, immutable)")
    for e in protocol.audit.get_full_history("spend-agent-01"):
        d = e.get("data", {})
        et = e.get("event_type", "?")
        target = d.get("target") or d.get("action_type") or ""
        cost = d.get("cost") or d.get("estimated_cost") or 0
        print(f"  [{et}] {target}  ${float(cost):.2f}")


if __name__ == "__main__":
    main()
