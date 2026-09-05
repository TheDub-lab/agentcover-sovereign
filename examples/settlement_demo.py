#!/usr/bin/env python3
"""
Real settlement example — testnet-safe.

Shows the production money path WITHOUT moving real funds:
  1. The gate clears the action (deny-by-default, exact recipient, cap).
  2. settle_real() is called — but LIVE is False, so it refuses to touch
     a chain. This is the safety default: no surprise on-chain action.
  3. We also build the EIP-3009 authorization STRUCT that a real wallet
     would sign (shown, not broadcast) so you can see the exact payload.

To go live for real:
  - pip install eth_account
  - create/fund a Base wallet out-of-band (HSM / secret manager)
  - RealWallet(private_key=..., live=True) + SafeSpendAgent(live=True)
  - then settle_real() signs + you POST to a x402 facilitator / USDC contract

Run:  python examples/settlement_demo.py
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from safety_protocol.core import AuditTrail, ScopeRule
from safety_protocol.protocol import SafetyProtocol
from safety_protocol.payments import SafeSpendAgent
from safety_protocol.real_wallet import RealWallet, HAS_REAL_CRYPTO

TRUSTED = "0xMerchant1111111111111111111111111111111111"


def build_protocol():
    return SafetyProtocol(
        agent_id="spend-agent-01",
        user_id="alice",  # the accountable human
        scope_rules=[
            ScopeRule(
                action_type="payment",
                allowed_targets=[TRUSTED],
                match="exact",
                methods=["x402"],
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
                max_cost=1.00,
            ),
        ],
        budget_limit=5.00,
        approval_threshold_cost=0.50,
        allowed_action_types=["payment"],
    )


def main():
    protocol = build_protocol()
    # In demo mode: SimWallet (HMAC) for local runs; RealWallet wired but
    # NOT live, so no chain is ever touched.
    real = RealWallet(live=False)
    agent = SafeSpendAgent(protocol=protocol, real_wallet=real, live=False)

    print("=" * 70)
    print("REAL SETTLEMENT PATH (testnet-safe — no funds move)")
    print("=" * 70)
    print(f"  eth_account available: {HAS_REAL_CRYPTO}")
    print(f"  agent.live (would touch chain): {agent.live}")
    print()

    # (1) Gate clears a normal payment
    print("[1] Gate clears a $0.10 payment to the trusted merchant")
    r = agent.direct_pay(TRUSTED, 0.10, resource="weather")
    print(f"    outcome: {r.outcome}  (signed by SimWallet, not real chain)")
    print(f"    signed? {'yes' if r.envelope else 'no'}")
    print()

    # (2) settle_real() must REFUSE in demo mode — the safety default
    print("[2] Calling settle_real() in demo mode (LIVE=False)")
    try:
        agent.settle_real(TRUSTED, 0.10)
        print("    UNEXPECTED: settle succeeded without LIVE=True")
        sys.exit(1)
    except RuntimeError as e:
        print(f"    correctly refused: {e}")
    print()

    # (3) Show the EXACT EIP-3009 authorization a real wallet would sign
    print("[3] The EIP-3009 USDC authorization struct (built, not sent)")
    if HAS_REAL_CRYPTO:
        rw = RealWallet.generate(live=False)
        auth = rw.build_eip3009_authorization(
            to=TRUSTED, value_base_units=100_000)  # 0.10 USDC (6dp)
        print(f"    signer address: {rw.address}")
        print(f"    to:             {auth['message']['to']}")
        print(f"    value (base):   {auth['message']['value']}")
        print(f"    validAfter:     {auth['message']['validAfter']}")
        print(f"    validBefore:    {auth['message']['validBefore']}")
        print(f"    nonce:          {auth['message']['nonce'][:18]}...")
        print(f"    digest:         {auth['digest'][:42]}...")
        print("    -> POST {typed_data + signature} to a x402 facilitator or")
        print("       submit transferWithAuthorization to the USDC contract.")
    else:
        print("    (eth_account not installed here — the struct is identical,")
        print("     just unverifiable in this sandbox. Install eth_account")
        print("     to generate a real key + digest locally.)")
    print()

    print("=" * 70)
    print("WHY THIS IS SAFE TO SHIP")
    print("=" * 70)
    print("  - The gate runs BEFORE any signing. Blocked/pending -> no sig.")
    print("  - LIVE defaults False. Real settlement is opt-in and explicit.")
    print("  - No key is loaded unless you pass one. No funds move by default.")
    print("  - When LIVE, RealWallet uses EIP-3009 (USDC transferWithAuth),")
    print("    the standard x402 settlement primitive on Base.")
    print()
    print("RESULT: demo-safe, production-shaped. OK.")


if __name__ == "__main__":
    main()
