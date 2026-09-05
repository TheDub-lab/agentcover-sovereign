#!/usr/bin/env python3
"""
Mock x402 merchant — stdlib HTTP server (no dependencies).

Emits a real HTTP 402 with a PAYMENT-REQUIRED envelope (x402 V2 shape),
then on retry verifies the PAYMENT-SIGNATURE and returns the paid resource.

Run:  python examples/mock_merchant.py
Then point SafeSpendAgent.pay() at http://127.0.0.1:4020/weather

This is a DEMO merchant: it verifies the envelope signature using the same
shared secret the demo wallet uses (HMAC). A real merchant offloads this
to an x402 facilitator (Coinbase CDP, etc.) that settles on-chain.
"""

import base64
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

# Mirror the demo wallet's secret so the merchant can verify the signature.
WALLET_SECRET = "demo-secret-do-not-use-in-production"
USDC_BASE = 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913
NETWORK = "eip155:8453"
PRICE_USD = 0.10  # $0.10 per call


def _hmac(payload: bytes) -> str:
    import hashlib, hmac
    return hmac.new(WALLET_SECRET.encode(), payload, hashlib.sha256).hexdigest()


def build_terms() -> str:
    amount = int(PRICE_USD * 1_000_000)
    env = {
        "x402Version": 2,
        "paymentRequirements": [
            {
                "scheme": "exact",
                "network": NETWORK,
                "asset": hex(USDC_BASE),
                "payTo": "0xMerchant1111111111111111111111111111111111",
                "maxAmountRequired": amount,
                "resource": "GET /weather",
                "description": "Weather data",
            }
        ],
    }
    return base64.b64encode(json.dumps(env).encode()).decode()


def verify_signature(wire: str) -> bool:
    try:
        d = json.loads(base64.b64decode(wire))
        payload = json.dumps(
            {
                "scheme": d["scheme"],
                "network": d["network"],
                "asset": d["asset"],
                "from": d["from"],
                "to": d["to"],
                "value": d["value"],
                "validAfter": d["validAfter"],
                "validBefore": d["validBefore"],
                "nonce": d["nonce"],
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        return d["signature"] == _hmac(payload)
    except Exception:
        return False


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        if self.path != "/weather":
            self.send_response(404)
            self.end_headers()
            return
        sig = self.headers.get("PAYMENT-SIGNATURE")
        if not sig:
            body = b"Payment Required"
            self.send_response(402)
            self.send_header("PAYMENT-REQUIRED", build_terms())
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        # Verify the signed authorization.
        if not verify_signature(sig):
            self.send_response(402)
            self.end_headers()
            return
        body = json.dumps({
            "resource": "weather",
            "temperature": 21.5,
            "note": "paid via x402, authorized by safety gate",
            "settled_at": int(time.time()),
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # quiet
        pass


def run(port: int = 4020):
    srv = HTTPServer(("127.0.0.1", port), Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


if __name__ == "__main__":
    srv = run()
    print(f"Mock x402 merchant on http://127.0.0.1:4020/weather  (price ${PRICE_USD})")
    print("Press Ctrl-C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        srv.shutdown()
