#!/usr/bin/env python3
"""
Live settlement test — Base Sepolia (TESTNET only).

SAFE DEFAULT:  LIVE_SETTLE = False
  Runs the FULL gate -> RealWallet.settle() -> EIP-3009 sign path using the
  REAL key in testnet_wallets.json, then verifies the signature locally by
  recovering the signer. This proves the real crypto end-to-end against the
  actual Base Sepolia USDC contract parameters. No chain is touched — no
  funds move, no gas spent.

FLIP TO TRUE ONLY AFTER:
  1. You have funded testnet_wallets.json's payer with Base Sepolia ETH (gas)
     AND Circle testnet USDC (the thing being sent).
  2. You have independently confirmed SEPOLIA_USDC and SEPOLIA_RPC are correct
     for the day you run it (addresses/endpoints change — verify, don't trust).
  3. You accept that this will broadcast a real on-chain transfer (testnet
     funds, but real gas, real tx, real tx hash).

When LIVE_SETTLE=True the script:
  - gates the intent (SafetyProtocol — same gate your demo proves)
  - signs a real EIP-3009 transferWithAuthorization with the agent's key
  - splits the signature (v,r,s) and broadcasts it to the USDC contract
  - reads the merchant's USDC balance before/after to PROVE settlement
  - prints the tx hash you can verify on sepolia.basescan.org

Run:  python examples/live_settlement_test.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from eth_account import Account
from eth_account.messages import encode_typed_data
from safety_protocol.core import ScopeRule
from safety_protocol.protocol import SafetyProtocol
from safety_protocol.payments import SafeSpendAgent
from safety_protocol.real_wallet import RealWallet, HAS_REAL_CRYPTO

# -- config ---------------------------------------------------------------
LIVE_SETTLE = False   # flip to True to broadcast (needs funded payer)

# RPC resolution: BASE_RPC_URL from .env (keyed Alchemy) wins; falls back to
# the public endpoint. Never hardcode a key in this file.
def _load_env(path):
    env = {}
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip().strip('"').strip("'")
    except FileNotFoundError:
        pass
    return env

_cfg = _load_env(os.path.join(os.path.dirname(__file__), "..", ".env"))
SEPOLIA_RPC = _cfg.get("BASE_RPC_URL") or "https://sepolia.base.org"
SEPOLIA_USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
CHAIN_ID = 84532
PAY_USD = 0.015       # tiny test amount (15,000 base units @ 6dp)

WALLETS = os.path.join(os.path.dirname(__file__), "..", "testnet_wallets.json")


def load_cfg():
    if not os.path.exists(WALLETS):
        sys.exit("testnet_wallets.json not found. Run "
                 "examples/generate_testnet_wallets.py first.")
    with open(WALLETS) as f:
        return json.load(f)


def build_protocol(payee: str) -> SafetyProtocol:
    """Exact-recipient scope: the agent may only pay THIS merchant, via x402,
    for a 'weather' resource, capped at $1.00/ payment."""
    rule = ScopeRule(
        action_type="payment",
        allowed_targets=[payee],
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
    )
    return SafetyProtocol(
        agent_id="spend-agent-01",
        user_id="alice",
        scope_rules=[rule],
        budget_limit=5.00,
        approval_threshold_cost=0.50,
        allowed_action_types=["payment"],
    )


def main():
    if not HAS_REAL_CRYPTO:
        sys.exit("eth_account not installed — run: uv pip install "
                 "--python <hermes-venv>/Scripts/python.exe eth_account")
    cfg = load_cfg()
    payer_addr = cfg["payer_address"]
    payer_key = cfg["payer_private_key_hex"]
    payee_addr = cfg["payee_address"]

    print("=" * 70)
    print(f"LIVE SETTLEMENT TEST  (LIVE_SETTLE={LIVE_SETTLE})  — Base Sepolia")
    print("=" * 70)
    print(f"  payer (agent): {payer_addr}")
    print(f"  payee (merch): {payee_addr}")
    print(f"  amount:        ${PAY_USD} USDC")
    print()

    # Real wallet + agent, both LIVE. settle_real() still refuses unless the
    # gate clears — LIVE here means "may touch chain", not "will".
    rw = RealWallet(
        private_key=payer_key, live=True,
        chain_id=CHAIN_ID, usdc_address=SEPOLIA_USDC,
    )
    agent = SafeSpendAgent(
        protocol=build_protocol(payee_addr), real_wallet=rw, live=True,
    )

    # (1) GATE + REAL SIGN — runs in both modes. This is the part that proves
    #     the agent's key actually authorizes a payment the gate approved.
    print("[1] Gate clears the intent, agent signs a REAL EIP-3009 auth")
    auth = agent.settle_real(payee_addr, PAY_USD)
    sm = encode_typed_data(full_message=auth["typed_data"])
    recovered = Account.recover_message(
        sm, signature=bytes.fromhex(auth["signature"]))
    ok = recovered.lower() == payer_addr.lower()
    print(f"    outcome: signed, signer recovered = {recovered}")
    print(f"    signer matches payer: {ok}")
    assert ok, "signature did not recover the payer — abort"
    print()

    if not LIVE_SETTLE:
        print("[2] LIVE_SETTLE is False — stopping before any chain action.")
        print("    The signature above is REAL but unbroadcast.")
        print("    Fund the payer, verify SEPOLIA_USDC/SEPOLIA_RPC, then set")
        print("    LIVE_SETTLE = True and re-run to execute the transfer.")
        print()
        print("RESULT: real gate + real signature verified. No funds moved.")
        return

    # (2) BROADCAST — only reached when LIVE_SETTLE=True.
    from web3 import Web3
    w3 = Web3(Web3.HTTPProvider(SEPOLIA_RPC))
    try:
        node_chain = w3.eth.chain_id
    except Exception as e:
        sys.exit(f"cannot reach RPC {SEPOLIA_RPC}: {e}")
    if node_chain != CHAIN_ID:
        sys.exit(f"RPC chainId {node_chain} != expected Base Sepolia {CHAIN_ID}")

    # NOTE: the payer MUST hold Sepolia ETH for gas. A native-ETH transfer as a
    # "fallback" still needs gas, so it is NOT a fallback when the payer has 0
    # ETH. Fund the payer with Sepolia ETH (Alchemy `faucet drip` or a public
    # Base Sepolia faucet) before flipping LIVE_SETTLE=True. With gas present,
    # the USDC EIP-3009 transferWithAuthorization below runs as designed.
    if w3.eth.get_balance(payer_addr) == 0:
        sys.exit(
            "PAYER HAS NO GAS (0 Sepolia ETH). Cannot broadcast any tx. "
            "Fund the payer with Sepolia ETH first, then re-run with "
            "LIVE_SETTLE=True. USDC is present; only gas is missing."
        )

    abi = [{
        "constant": False, "inputs": [
            {"name": "from", "type": "address"},
            {"name": "to", "type": "address"},
            {"name": "value", "type": "uint256"},
            {"name": "validAfter", "type": "uint256"},
            {"name": "validBefore", "type": "uint256"},
            {"name": "nonce", "type": "bytes32"},
            {"name": "v", "type": "uint8"},
            {"name": "r", "type": "bytes32"},
            {"name": "s", "type": "bytes32"},
        ], "name": "transferWithAuthorization", "outputs": [{"name": "", "type": "bool"}],
        "stateMutability": "nonpayable", "type": "function",
    }, {
        "constant": True, "inputs": [{"name": "account", "type": "address"}],
        "name": "balanceOf", "outputs": [{"name": "", "type": "uint256"}],
        "stateMutability": "view", "type": "function",
    }]
    usdc = w3.eth.contract(address=SEPOLIA_USDC, abi=abi)

    m = auth["message"]
    sig = bytes.fromhex(auth["signature"])
    r, s, v = sig[:32], sig[32:64], sig[64]
    nonce_bytes = bytes.fromhex(m["nonce"][2:])

    bal_before = usdc.functions.balanceOf(payee_addr).call()

    print("[2] Broadcasting transferWithAuthorization to USDC contract...")
    tx = usdc.functions.transferWithAuthorization(
        m["from"], m["to"], int(m["value"]),
        int(m["validAfter"]), int(m["validBefore"]),
        nonce_bytes, v, r, s,
    ).build_transaction({
        "from": payer_addr,
        "nonce": w3.eth.get_transaction_count(payer_addr),
        "gas": 200000,
        "gasPrice": w3.eth.gas_price,
        "chainId": CHAIN_ID,
    })
    signed = w3.eth.account.sign_transaction(tx, payer_key)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    print(f"    tx: {tx_hash.hex()}  status={receipt.status}")

    bal_after = usdc.functions.balanceOf(payee_addr).call()
    moved = bal_after - bal_before
    print(f"    payee USDC before: {bal_before}")
    print(f"    payee USDC after : {bal_after}")
    print(f"    settled         : {moved} base units "
          f"(${moved/1e6:.6f} USDC)")
    assert receipt.status == 1, "tx reverted"
    assert moved == int(m["value"]), "settled amount mismatch"
    print()
    print("RESULT: LIVE settlement confirmed on Base Sepolia. "
          "Verify at https://sepolia.basescan.org/tx/" + tx_hash.hex())


if __name__ == "__main__":
    main()
