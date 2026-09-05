"""
Real settlement wallet — production signing path for x402 / USDC on Base.

This module holds the REAL signing backend. The rest of the framework
uses SimWallet (HMAC, zero-dep) so the demo runs anywhere. This class is
what you swap in for production: it signs EIP-3009-style authorizations
with a real secp256k1 key via `eth_account`.

Two gates keep it honest:
  - HAS_REAL_CRYPTO: False if `eth_account` isn't installed. The wallet
    will refuse to operate in real mode and tell you so.
  - LIVE: the SafeSpendAgent only calls a chain/facilitator when LIVE=True.
    Default is False. Real money does not move unless you explicitly set
    LIVE=True AND provide a funded wallet. No surprise on-chain actions.

USDC on Base uses EIP-3009 `transferWithAuthorization`:
    authorize(owner, to, value, validAfter, validBefore, nonce, sig)
The signed message is the EIP-712 typed-data digest of that struct.
This class builds and signs that digest. Submitting it to the USDC
contract (or a x402 facilitator that does) is the settlement step — left
to the caller / facilitator, behind the gate.

Install for production:  pip install eth-account
"""

from __future__ import annotations
import os
import time
import uuid
from typing import Any

try:
    from eth_account import Account
    from eth_account.messages import encode_typed_data
    HAS_REAL_CRYPTO = True
except Exception:  # pragma: no cover - depends on environment
    HAS_REAL_CRYPTO = False
    Account = None  # type: ignore
    encode_typed_data = None  # type: ignore


# EIP-712 domain for USDC (chainId differs by network)
# Mainnet USDC: 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48, chainId 1
# Base USDC:    0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913, chainId 8453
USDC_DOMAIN = {
    "name": "USD Coin",
    "version": "2",
}


class RealWallet:
    """Signs x402 payment authorizations with a real secp256k1 key.

    Holds a private key OUT OF BAND. In production, load it from a secret
    manager / HSM, never from source or env committed to the repo. The
    key is required only to sign; the public address is what the gate
    and the merchant see.
    """

    def __init__(
        self,
        private_key: str | None = None,
        live: bool = False,
        usdc_address: str = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
        chain_id: int = 8453,  # Base mainnet
    ):
        if live and not HAS_REAL_CRYPTO:
            raise RuntimeError(
                "LIVE=True but `eth_account` is not installed. "
                "Run `pip install eth_account` before going live."
            )
        self.live = live
        self.usdc_address = usdc_address
        self.chain_id = chain_id
        if private_key:
            if not HAS_REAL_CRYPTO:
                raise RuntimeError("eth_account required to load a real key")
            self._acct = Account.from_key(private_key)
        else:
            self._acct = None

    # -- key lifecycle --------------------------------------------------
    @classmethod
    def generate(cls, live: bool = False, **kw) -> "RealWallet":
        """Create a fresh keypair (for testnet / dev only)."""
        if not HAS_REAL_CRYPTO:
            raise RuntimeError("eth_account required to generate keys")
        acct = Account.create()
        w = cls(private_key=acct.key.hex(), live=live, **kw)
        return w

    @property
    def address(self) -> str:
        if self._acct is None:
            return "0xREAL_WALLET_NOT_LOADED"
        return self._acct.address

    @property
    def has_real_crypto(self) -> bool:
        return HAS_REAL_CRYPTO

    # -- EIP-3009 authorization ----------------------------------------
    def build_eip3009_authorization(
        self,
        to: str,
        value_base_units: int,
        valid_after: int | None = None,
        valid_before: int | None = None,
        nonce: str | None = None,
    ) -> dict:
        """Build the EIP-712 typed-data struct for USDC transferWithAuthorization.

        Returns the full typed-data dict (domain + types + message) and the
        encoded digest. Does NOT broadcast.
        """
        if self._acct is None:
            raise RuntimeError("wallet has no key loaded")
        now = int(time.time())
        valid_after = valid_after if valid_after is not None else now - 30
        valid_before = valid_before if valid_before is not None else now + 120
        nonce = nonce or (uuid.uuid4().hex + uuid.uuid4().hex)  # 32 bytes

        types = {
            "TransferWithAuthorization": [
                {"name": "from", "type": "address"},
                {"name": "to", "type": "address"},
                {"name": "value", "type": "uint256"},
                {"name": "validAfter", "type": "uint256"},
                {"name": "validBefore", "type": "uint256"},
                {"name": "nonce", "type": "bytes32"},
            ]
        }
        message = {
            "from": self.address,
            "to": to,
            "value": value_base_units,
            "validAfter": valid_after,
            "validBefore": valid_before,
            "nonce": "0x" + nonce,
        }
        domain = dict(USDC_DOMAIN)
        domain["chainId"] = self.chain_id
        domain["verifyingContract"] = self.usdc_address
        typed = {"domain": domain, "types": types, "primaryType":
                 "TransferWithAuthorization", "message": message}

        signable = encode_typed_data(full_message=typed) if HAS_REAL_CRYPTO else None
        # encode_typed_data returns a SignableMessage (version, header, body).
        # `body` IS the EIP-712 digest (0x19 0x01 || domainSeparator ||
        # structHash). sign_message signs over body, so the stored digest is
        # body.hex() — and a verifier recovers over the same bytes.
        digest = signable.body if signable else None
        return {"typed_data": typed, "digest": digest.hex() if digest else None,
                "message": message}

    def sign_eip3009(self, authorization: dict) -> str:
        """Sign the authorization with the real key (EIP-712).

        `authorization` is the dict returned by build_eip3009_authorization,
        which carries the full typed_data. eth_account signs the
        SignableMessage directly; no manual digest handling needed.
        """
        if not HAS_REAL_CRYPTO or self._acct is None:
            raise RuntimeError("real crypto unavailable — cannot sign")
        signable = encode_typed_data(full_message=authorization["typed_data"])
        signed = self._acct.sign_message(signable)
        return signed.signature.hex()

    def settle(self, recipient: str, value_base_units: int) -> dict:
        """Produce a signed EIP-3009 authorization for `recipient`.

        In production this dict (typed_data + signature + message) is what
        you POST to a x402 facilitator or submit to the USDC contract. The
        SafeSpendAgent only reaches here AFTER the SafetyProtocol gate
        cleared the action — the signature is the last, gated step.
        """
        if not self.live:
            raise RuntimeError(
                "settle() called with LIVE=False — real settlement is a "
                "gated, opt-in step. Set live=True and load a funded key."
            )
        auth = self.build_eip3009_authorization(recipient, value_base_units)
        sig = self.sign_eip3009(auth)
        return {
            "from": self.address,
            "to": recipient,
            "value": value_base_units,
            "signature": sig,
            "typed_data": auth["typed_data"],
        }
