"""
On-chain USDC payment verification — the safety-protocol's post-settlement
confirmation primitive for the x402 guard.

Usage in the x402 flow:
  1. SafeSpendAgent.gate() clears the action.
  2. (production) wallet signs + facilitator/submitter broadcasts the EIP-3009
     authorization; a tx_hash becomes available.
  3. onchain_payment_verifier.confirm_payment(tx_hash, expected_payee, min_usdc)
     proves the USDC actually reached the intended recipient before the
     settlement is marked "done".

This is the on-chain part of "agent moves money via x402 only after the
SafetyProtocol gate clears." The gate runs FIRST; this verifies the result
settled on-chain.

Design keeps with the rest of the framework:
  - keyless by default (uses the public Base RPC). Set BASE_RPC_URL for
    heavier polling once you have an Alchemy/Infura key.
  - fails closed: any RPC error returns ok=False rather than claiming success.
  - no new dependencies beyond `requests` (already in the environment).
"""

from __future__ import annotations

import os
import sys
from typing import Any

try:
    import requests
except ImportError:
    requests = None  # type: ignore

# Base USDC on Base mainnet (Circle).
USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
USDC_DECIMALS = 6

# Defaults to the keyless public RPC; override via env for heavier use.
RPC_URL = os.environ.get("BASE_RPC_URL", "https://mainnet.base.org")


# ---------------------------------------------------------------------------
# internal helpers (copied/derived from base_usdc_monitor — the proven logic)
# ---------------------------------------------------------------------------
def _pad_addr(addr: str) -> str:
    return "0x" + addr.lower().replace("0x", "").rjust(64, "0")

def _to_int(hexval) -> int:
    return int(hexval, 16) if hexval else 0

def _rpc(method: str, params: list, session: requests.Session, timeout: int = 30) -> Any:
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    r = session.post(RPC_URL, json=payload, timeout=timeout,
                     headers={"User-Agent": "Mozilla/5.0", "Content-Type": "application/json"})
    r.raise_for_status()
    data = r.json()
    if "error" in data:
        raise RuntimeError(f"RPC error: {data['error']}")
    return data.get("result")

def _decode_transfer(log: dict) -> dict:
    from_addr = "0x" + log["topics"][1][-40:]
    to_addr = "0x" + log["topics"][2][-40:]
    amount = _to_int(log.get("data", "0x0"))
    return {
        "from": from_addr,
        "to": to_addr,
        "amount_raw": amount,
        "amount_usdc": amount / 10 ** USDC_DECIMALS,
        "tx_hash": log.get("transactionHash"),
        "block": _to_int(log.get("blockNumber")),
    }


# ---------------------------------------------------------------------------
# public API
# ---------------------------------------------------------------------------
class OnChainPaymentVerifier:
    """Confirms a USDC payment actually landed on-chain to the expected recipient.

    Thin wrapper around the proven monitor logic. Instantiate once per process
    (it holds a requests.Session); call confirm_payment() per settlement.
    """

    def __init__(self, rpc_url: str | None = None):
        if requests is None:
            raise RuntimeError("requests is required for on-chain verification")
        self._rpc_url = rpc_url or RPC_URL
        self._session = requests.Session()

    # -- single-payment confirmation (the x402 guard calls this) ----------
    def confirm_payment(
        self,
        tx_hash: str,
        expected_to: str,
        min_usd: float = 0.01,
    ) -> dict:
        """Prove a USDC transfer of >= min_usd to `expected_to` landed in tx.

        Returns:
            {"ok": bool, "amount_usdc": float|None, "from": str|None,
             "reason": str, "tx_hash": str, "block": int|None}

        Fails closed: network/RPC errors return ok=False rather than claiming
        the payment succeeded.
        """
        try:
            receipt = self._rpc("eth_getTransactionReceipt", [tx_hash])
        except Exception as e:
            return {
                "ok": False, "tx_hash": tx_hash, "reason": f"RPC error: {e}",
                "amount_usdc": None, "from": None, "block": None,
            }
        if not receipt:
            return {
                "ok": False, "tx_hash": tx_hash,
                "reason": "no receipt (pending or invalid hash)",
                "amount_usdc": None, "from": None, "block": None,
            }

        block = _to_int(receipt.get("blockNumber"))
        for log in receipt.get("logs", []):
            if log.get("address", "").lower() != USDC_BASE.lower():
                continue
            if log.get("topics", [None])[0] != TRANSFER_TOPIC:
                continue
            dec = _decode_transfer(log)
            if dec["to"].lower() == expected_to.lower() and dec["amount_usdc"] >= min_usd:
                return {
                    "ok": True, "tx_hash": tx_hash, "block": block,
                    "amount_usdc": dec["amount_usdc"], "from": dec["from"],
                    "reason": "confirmed on-chain",
                }
        return {
            "ok": False, "tx_hash": tx_hash, "block": block,
            "reason": "no qualifying USDC transfer in receipt",
            "amount_usdc": None, "from": None,
        }

    # -- convenience: latest block ------------------------------------------
    def latest_block(self) -> int:
        return _to_int(self._rpc("eth_blockNumber", []))

    # -- internal (avoid re-binding _rpc as a bound method) -----------------
    def _rpc(self, method: str, params: list):
        return _rpc(method, params, self._session)


# ---------------------------------------------------------------------------
# cli (keeps a usable tool at the framework's edge, separate from the guard)
# ---------------------------------------------------------------------------
def _cli() -> int:
    import argparse
    ap = argparse.ArgumentParser(description="On-chain USDC payment verifier")
    ap.add_argument("--tx", required=True, help="transaction hash to verify")
    ap.add_argument("--to", required=True, help="expected USDC recipient address")
    ap.add_argument("--min", type=float, default=0.01, help="minimum USDC")
    ap.add_argument("--rpc", default=None, help="override RPC_URL")
    args = ap.parse_args()
    v = OnChainPaymentVerifier(rpc_url=args.rpc)
    res = v.confirm_payment(args.tx, args.to, args.min)
    print(f"tx_hash={res['tx_hash']}")
    print(f"ok={res['ok']} reason={res['reason']}")
    if res.get("amount_usdc") is not None:
        print(f"amount_usdc={res['amount_usdc']:.6f} from={res['from']}")
    if res.get("block") is not None:
        print(f"block={res['block']:,}")
    return 0 if res["ok"] else 1


if __name__ == "__main__":
    sys.exit(_cli())
