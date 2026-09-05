#!/usr/bin/env python3
"""
Generate a REAL keypair for the live settlement test (Base Sepolia, testnet).

What this does:
  1. Creates a payer keypair (the agent) via RealWallet.generate().
  2. Creates a payee address (the merchant) — key discarded, address only.
  3. Verifies the EIP-3009 signing round-trip locally (sign -> recover signer).
     This proves the REAL crypto path works before any chain is touched.
  4. Writes testnet_wallets.json (gitignored). Keys never hit the repo.

It does NOT fund the wallet, and it does NOT broadcast. Funding + LIVE=True
happen in a later, explicit step.

Run:  python examples/generate_testnet_wallets.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from eth_account import Account
from safety_protocol.real_wallet import RealWallet, HAS_REAL_CRYPTO

# Base Sepolia testnet constants. CONFIRM the USDC address on the Circle
# faucet page before relying on it: https://faucet.circle.com
BASE_SEPOLIA_CHAIN_ID = 84532
BASE_SEPOLIA_USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"

OUT = os.path.join(os.path.dirname(__file__), "..", "testnet_wallets.json")


def main():
    if not HAS_REAL_CRYPTO:
        sys.exit("eth_account not installed. Run: uv pip install --python "
                 "<hermes-venv>/Scripts/python.exe eth_account")

    # (1) Payer = the agent. Holds the key, will sign EIP-3009.
    payer = RealWallet.generate(
        live=False,
        chain_id=BASE_SEPOLIA_CHAIN_ID,
        usdc_address=BASE_SEPOLIA_USDC,
    )

    # (2) Payee = the merchant. Address only; no key needed.
    payee = Account.create()

    print("=" * 70)
    print("REAL KEYPAIR GENERATED (Base Sepolia testnet)")
    print("=" * 70)
    print(f"  payer (agent) address: {payer.address}")
    print(f"  payee (merchant) addr: {payee.address}")

    # (3) Prove the signing path works: build + sign + recover.
    auth = payer.build_eip3009_authorization(
        to=payee.address, value_base_units=15_000  # 0.015 USDC (6dp)
    )
    sig = payer.sign_eip3009(auth)
    from eth_account.messages import encode_typed_data
    signable = encode_typed_data(full_message=auth["typed_data"])
    recovered = Account.recover_message(signable, signature=bytes.fromhex(sig))
    ok = recovered.lower() == payer.address.lower()
    print(f"  EIP-3009 sign+recover round-trip: {'PASS' if ok else 'FAIL'}")
    assert ok, "signature did not recover the signer — aborting, key not saved"

    # (4) Persist. Private key is sensitive; file is gitignored.
    data = {
        "network": "base-sepolia",
        "chain_id": BASE_SEPOLIA_CHAIN_ID,
        "usdc_address": BASE_SEPOLIA_USDC,
        "payer_address": payer.address,
        "payer_private_key_hex": payer._acct.key.hex(),
        "payee_address": payee.address,
        "note": "Testnet only. Fund via faucets, then set LIVE=True to settle.",
    }
    with open(OUT, "w") as f:
        json.dump(data, f, indent=2)
    print(f"  saved to: {os.path.normpath(OUT)}  (gitignored)")
    print()
    print("NEXT:")
    print("  - Fund payer address with Sepolia ETH (gas) + Circle testnet USDC")
    print("  - Run examples/live_settlement_test.py (scaffold provided separately)")
    print("  - Only flip LIVE=True after you confirm funds landed.")


if __name__ == "__main__":
    main()
