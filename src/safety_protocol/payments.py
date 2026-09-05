"""
Safe payment / spend agent — x402 guard.

This is the product layer: an agent that can move money (via the x402
payment protocol) but ONLY after the SafetyProtocol gate clears the
action. Scope (recipient allow/deny), per-payment cap, rolling budget,
approval threshold, and kill-switch all sit BETWEEN the agent's intent
and the wallet's signature.

Critical property: the wallet NEVER signs a payment the gate didn't
approve. A blocked or pending-approval action never reaches signing.

x402 V2 flow (https://github.com/x402-foundation/x402):
  1. Agent calls a paid endpoint.
  2. Server returns 402 Payment Required + PAYMENT-REQUIRED envelope
     (CAIP-2 network, asset, recipient, amount, expiry, facilitator).
  3. Agent signs an EIP-3009-style authorization (USDC transferWithAuthorization).
  4. Agent retries with PAYMENT-SIGNATURE header.
  5. Facilitator verifies + settles on-chain; server returns 200.

This module wraps steps 2-4 behind the safety gate. The signature here
uses HMAC-SHA256 over the canonical envelope (stdlib, zero deps) so the
demo runs anywhere. In production, swap SimWallet for an EIP-3009 signer
(eth_account / EIP-712) — the envelope and gate logic are unchanged.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from .core import ActionOutcome, ActionRequest
from .protocol import SafetyProtocol
from .real_wallet import RealWallet, HAS_REAL_CRYPTO
from .onchain_payment_verifier import OnChainPaymentVerifier

DEFAULT_NETWORK = "eip155:8453"  # Base mainnet (CAIP-2)
DEFAULT_ASSET = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"  # USDC on Base


# ---------------------------------------------------------------------------
# Simulated wallet (pluggable signer)
# ---------------------------------------------------------------------------
class SimWallet:
    """Local HMAC wallet for the demo.

    Production: replace with a real EIP-3009 signer (secp256k1 ECDSA over
    the EIP-712 typed-data hash). The sign()/verify() contract and the
    envelope shape stay identical.
    """

    def __init__(self, secret: str | None = None):
        self.secret = secret or os.urandom(32).hex()
        self.address = "0x" + hashlib.sha256(self.secret.encode()).hexdigest()[:40]

    def sign(self, payload: bytes) -> str:
        return hmac.new(self.secret.encode(), payload, hashlib.sha256).hexdigest()

    def verify(self, payload: bytes, signature: str) -> bool:
        return hmac.compare_digest(self.sign(payload), signature)


# ---------------------------------------------------------------------------
# x402-style payment envelope
# ---------------------------------------------------------------------------
@dataclass
class PaymentEnvelope:
    """A signed payment authorization — structurally x402 V2 / EIP-3009."""

    scheme: str                       # "exact" (fixed) — x402 payment scheme
    network: str                      # CAIP-2, e.g. "eip155:8453"
    asset: str                        # token contract address
    from_addr: str                    # payer (agent wallet)
    to_addr: str                      # recipient (merchant)
    value: int                        # amount in base units (USDC = 6 decimals)
    valid_after: int                  # unix seconds
    valid_before: int                 # unix seconds
    nonce: str                        # 32-byte hex, random
    signature: str = ""               # set by sign()

    def canonical(self) -> bytes:
        """Canonical bytes signed/verified. Excludes the signature itself."""
        d = {
            "scheme": self.scheme,
            "network": self.network,
            "asset": self.asset,
            "from": self.from_addr,
            "to": self.to_addr,
            "value": self.value,
            "validAfter": self.valid_after,
            "validBefore": self.valid_before,
            "nonce": self.nonce,
        }
        # Stable, sorted serialization.
        return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()

    def to_wire(self) -> str:
        return base64.b64encode(
            json.dumps(
                {
                    "scheme": self.scheme,
                    "network": self.network,
                    "asset": self.asset,
                    "from": self.from_addr,
                    "to": self.to_addr,
                    "value": self.value,
                    "validAfter": self.valid_after,
                    "validBefore": self.valid_before,
                    "nonce": self.nonce,
                    "signature": self.signature,
                },
                sort_keys=True,
            ).encode()
        ).decode()

    @classmethod
    def from_wire(cls, wire: str) -> "PaymentEnvelope":
        d = json.loads(base64.b64decode(wire))
        return cls(
            scheme=d["scheme"],
            network=d["network"],
            asset=d["asset"],
            from_addr=d["from"],
            to_addr=d["to"],
            value=int(d["value"]),
            valid_after=int(d["validAfter"]),
            valid_before=int(d["validBefore"]),
            nonce=d["nonce"],
            signature=d.get("signature", ""),
        )


def amount_to_base_units(usd: float, decimals: int = 6) -> int:
    return int(round(usd * 10 ** decimals))


# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------
@dataclass
class PaymentResult:
    outcome: str                     # "paid" | "blocked" | "pending_approval"
    status_code: int | None = None
    body: Any = None
    reason: str = ""
    approval_token: str | None = None
    envelope: PaymentEnvelope | None = None
    request_id: str | None = None


# ---------------------------------------------------------------------------
# Safe spend agent
# ---------------------------------------------------------------------------
class SafeSpendAgent:
    """
    An agent that pays via x402, gated by a SafetyProtocol.

    The gate runs BEFORE any wallet signature. If the gate blocks or
    holds the action for approval, the wallet is never touched.
    """

    def __init__(
        self,
        protocol: SafetyProtocol,
        wallet: SimWallet | None = None,
        real_wallet: RealWallet | None = None,
        live: bool = False,
        network: str = DEFAULT_NETWORK,
        asset: str = DEFAULT_ASSET,
        facilitator: str = "https://x402.org/facilitator",
        decimals: int = 6,
        onchain_verifier: OnChainPaymentVerifier | None = None,
    ):
        # The protocol MUST register "payment" in its action vocabulary.
        if "payment" not in (protocol.allowed_action_types or []):
            raise ValueError(
                "SafetyProtocol must include 'payment' in allowed_action_types "
                "for the SafeSpendAgent to operate."
            )
        # Signer selection: a RealWallet + live=True is the production path
        # (real secp256k1 / EIP-3009 via eth_account). Otherwise we use the
        # zero-dep SimWallet so the demo runs anywhere. We never silently
        # claim to be live — HAS_REAL_CRYPTO is the source of truth.
        self.live = bool(live) and HAS_REAL_CRYPTO and real_wallet is not None
        self.real_wallet = real_wallet
        self.protocol = protocol
        self.wallet = wallet or SimWallet()
        self.network = network
        self.asset = asset
        self.facilitator = facilitator
        self.decimals = decimals
        # On-chain confirmation primitive (optional). When present, the agent
        # can prove a signed payment actually settled on-chain to the intended
        # recipient BEFORE marking the settlement as "done". Set via env
        # BASE_RPC_URL to a keyed provider for heavier / continuous use.
        self.onchain_verifier = onchain_verifier or OnChainPaymentVerifier()

    # -- real settlement (gated, opt-in) ---------------------------------
    def settle_real(self, recipient: str, usd: float, memo: str = "") -> dict:
        """Produce a REAL EIP-3009 USDC authorization — only after the gate.

        The SafetyProtocol gate runs FIRST. If it blocks or holds for
        approval, this raises before any signing. Only a cleared action
        reaches RealWallet.settle(). With LIVE=False this raises rather
        than produce a chain-touching signature — flip LIVE=True (and
        install eth_account + fund the wallet) to actually settle.
        """
        result, req = self._gate(recipient, usd, {"memo": memo})
        if result.outcome == ActionOutcome.BLOCKED_KILLSWITCH or result.block_reason:
            raise PermissionError(
                f"gate blocked real settlement: {result.block_reason}")
        if result.outcome == ActionOutcome.PENDING_APPROVAL:
            raise PermissionError(
                "real settlement held for approval "
                f"(token {result.requires_approval_for})")
        if not self.live or self.real_wallet is None:
            raise RuntimeError(
                "settle_real() requires LIVE=True, a loaded RealWallet, and "
                "eth_account installed. Real money does not move in demo mode.")
        return self.real_wallet.settle(
            recipient, amount_to_base_units(usd, self.decimals))

    # -- internal: gate an intent, return (ActionResult, PaymentEnvelope-or-None)
    def _gate(self, recipient: str, usd: float, extra: dict | None = None,
              resource: str = "weather") -> tuple:
        params = dict(extra or {})
        params.setdefault("resource", resource)
        req = ActionRequest(
            action_type="payment",
            target=recipient,
            method="x402",           # the only rail this scope permits
            estimated_cost=usd,
            params=params,
        )
        result = self.protocol.execute(req)
        return result, req

    # -- on-chain confirmation (proof the signed payment settled) --------
    def confirm_onchain(
        self,
        tx_hash: str,
        expected_to: str,
        min_usd: float = 0.01,
    ) -> dict:
        """Confirm a USDC payment settled on-chain to `expected_to` >= min_usd.

        Called by the production path AFTER a signed payment is submitted to
        the facilitator / USDC contract and a tx_hash is available. Returns
        the verification result; the settlement is only marked "done" when
        this returns ok=True for the expected recipient and amount.

        This is the "agent moves money via x402 only after the SafetyProtocol
        gate clears AND the on-chain settlement is confirmed" step. The gate
        runs FIRST (_gate / direct_pay / pay); this confirms the result
        settled as intended.
        """
        return self.onchain_verifier.confirm_payment(tx_hash, expected_to, min_usd)

    def _sign_envelope(self, recipient: str, usd: float) -> PaymentEnvelope:
        now = int(time.time())
        env = PaymentEnvelope(
            scheme="exact",
            network=self.network,
            asset=self.asset,
            from_addr=self.wallet.address,
            to_addr=recipient,
            value=amount_to_base_units(usd, self.decimals),
            valid_after=now - 30,
            valid_before=now + 120,
            nonce=uuid.uuid4().hex + uuid.uuid4().hex,  # 32 bytes
        )
        env.signature = self.wallet.sign(env.canonical())
        return env

    # -- agent-initiated spend (no 402 challenge) -------------------------
    def direct_pay(self, recipient: str, usd: float, memo: str = "",
                   resource: str = "weather") -> PaymentResult:
        result, req = self._gate(recipient, usd, {"memo": memo}, resource=resource)
        if result.outcome == ActionOutcome.BLOCKED_KILLSWITCH or result.block_reason:
            return PaymentResult(
                outcome="blocked",
                reason=result.block_reason or "blocked by safety protocol",
                request_id=req.request_id,
            )
        if result.outcome == ActionOutcome.PENDING_APPROVAL:
            return PaymentResult(
                outcome="pending_approval",
                approval_token=result.requires_approval_for,
                reason="held for human approval",
                request_id=req.request_id,
            )
        # allowed -> sign + (in production) submit to facilitator
        env = self._sign_envelope(recipient, usd)
        return PaymentResult(
            outcome="paid",
            envelope=env,
            reason="authorized and signed by gated wallet",
            request_id=req.request_id,
        )

    # -- x402 challenge/response flow -------------------------------------
    def pay(self, url: str, method: str = "GET", recipient: str | None = None) -> PaymentResult:
        # Step 1: first attempt, no payment.
        try:
            first = Request(url, method=method)
            urlopen(first, timeout=10).read()
            # Paid resource returned without a challenge — no payment needed.
            return PaymentResult(outcome="paid", status_code=200,
                                  reason="resource available without payment")
        except HTTPError as e:
            if e.code != 402:
                return PaymentResult(outcome="blocked",
                                      status_code=e.code,
                                      reason=f"server error {e.code}")
            terms = self._parse_terms(e)
            if terms is None:
                return PaymentResult(outcome="blocked", status_code=402,
                                      reason="malformed payment terms")
            rcpt = recipient or terms["recipient"]
            usd = terms["amount"] / (10 ** self.decimals)
            # Step 2: GATE the intent before signing anything.
            # Only the user-action params (resource) go through the scope
            # gate; url/network/asset are internal routing, not subject to
            # the param allowlist.
            result, req = self._gate(rcpt, usd, resource="weather")
            if result.block_reason or result.outcome == ActionOutcome.BLOCKED_KILLSWITCH:
                return PaymentResult(outcome="blocked", status_code=402,
                                      reason=result.block_reason or "blocked by safety protocol",
                                      request_id=req.request_id)
            if result.outcome == ActionOutcome.PENDING_APPROVAL:
                return PaymentResult(outcome="pending_approval",
                                      approval_token=result.requires_approval_for,
                                      reason="held for human approval",
                                      request_id=req.request_id)
            # Step 3: gate cleared -> sign + retry.
            env = self._sign_envelope(rcpt, usd)
            retry = Request(url, method=method)
            retry.add_header("PAYMENT-SIGNATURE", env.to_wire())
            try:
                resp = urlopen(retry, timeout=10)
                return PaymentResult(outcome="paid", status_code=resp.status,
                                      body=resp.read().decode("utf-8", "replace"),
                                      envelope=env, request_id=req.request_id)
            except HTTPError as e2:
                return PaymentResult(outcome="blocked", status_code=e2.code,
                                      reason=f"payment rejected: {e2.code}",
                                      request_id=req.request_id)

    # -- parse the 402 PaymentRequired envelope --------------------------
    @staticmethod
    def _parse_terms(err: HTTPError) -> dict | None:
        raw = err.headers.get("PAYMENT-REQUIRED")
        if not raw:
            return None
        try:
            env = json.loads(base64.b64decode(raw))
            # x402 V2 envelope nesting varies; pull the key fields.
            req = env.get("paymentRequirements", env)
            if isinstance(req, list):
                req = req[0]
            accepts = req.get("accepts", [req]) if isinstance(req.get("accepts"), list) else [req]
            a = accepts[0]
            scheme = a.get("scheme", {})
            return {
                "recipient": a.get("payTo") or scheme.get("payTo"),
                "amount": int(a.get("maxAmountRequired", 0)),
                "network": a.get("network", DEFAULT_NETWORK),
                "asset": a.get("asset", DEFAULT_ASSET),
            }
        except Exception:
            return None
