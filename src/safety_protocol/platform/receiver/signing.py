# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 Michael / TheDub-lab
"""
Receipt signing for the log receiver.

The signed receipt is the evidence: it proves a chain head existed at a
specific time and that the RECEIVER (not the partner) recorded it.

Preferred algorithm is Ed25519 (via ``cryptography``). When that dependency
is not installed we fall back to HMAC-SHA256 with a receiver-held secret —
still a verifiable MAC, and receipts carry a ``sig_alg`` field naming which
was used. Install the receiver extra (``cryptography``) for Ed25519.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os

try:  # pragma: no cover - depends on environment
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

    HAVE_ED25519 = True
except Exception:  # pragma: no cover
    HAVE_ED25519 = False


def _canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


class ReceiptSigner:
    """Signs receipts over (agent_id, head_seq, head_hash, received_at).

    ``key_hex`` may be supplied to persist the key across restarts; otherwise
    a fresh key is generated (the caller should persist ``private_key_hex()``).
    """

    def __init__(self, key_hex: str | None = None):
        if HAVE_ED25519:
            self.alg = "ed25519"
            if key_hex:
                self._key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(key_hex))
            else:
                self._key = Ed25519PrivateKey.generate()
        else:
            self.alg = "hmac-sha256"
            self._secret = bytes.fromhex(key_hex) if key_hex else os.urandom(32)

    def private_key_hex(self) -> str:
        if HAVE_ED25519:
            raw = self._key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
            return raw.hex()
        return self._secret.hex()

    def public_key_hex(self) -> str | None:
        if HAVE_ED25519:
            raw = self._key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            return raw.hex()
        return None

    def sign(self, receipt_fields: dict) -> str:
        msg = _canonical(receipt_fields)
        if HAVE_ED25519:
            return self._key.sign(msg).hex()
        return hmac.new(self._secret, msg, hashlib.sha256).hexdigest()

    def verify(self, receipt_fields: dict, sig: str) -> bool:
        msg = _canonical(receipt_fields)
        if HAVE_ED25519:
            try:
                pub = self._key.public_key() if self.alg == "ed25519" else None
            except Exception:  # pragma: no cover
                pub = None
            if pub is None:
                return False
            try:
                pub.verify(bytes.fromhex(sig), msg)
                return True
            except Exception:
                return False
        expected = hmac.new(self._secret, msg, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, sig)


def verify_receipt(receipt: dict, public_key_hex: str | None = None,
                   hmac_secret_hex: str | None = None) -> bool:
    """Verify a receipt and return the signed field set on success.

    ``sig_alg`` selects the verifier. Ed25519 verification needs the receiver
    public key; HMAC needs the shared secret.
    """
    fields = {
        "agent_id": receipt["agent_id"],
        "head_seq": receipt["head_seq"],
        "head_hash": receipt["head_hash"],
        "received_at": receipt["received_at"],
    }
    alg = receipt.get("sig_alg", "ed25519")
    if alg == "ed25519":
        if not HAVE_ED25519 or not public_key_hex:
            return False
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        try:
            pub.verify(bytes.fromhex(receipt["sig"]), _canonical(fields))
            return True
        except Exception:
            return False
    if alg == "hmac-sha256":
        if not hmac_secret_hex:
            return False
        expected = hmac.new(bytes.fromhex(hmac_secret_hex),
                            _canonical(fields), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, receipt["sig"])
    return False
