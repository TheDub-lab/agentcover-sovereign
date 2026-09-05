#!/usr/bin/env python3
"""
agent_client.py — a 'real' agent that calls the HTTP guard.

This is what an actual agent integration looks like: the agent forms an
intent, POSTs it to the guard, and only acts on an allow. It never sees
or edits the rules. Language-agnostic — any agent in any language hits
the same HTTP endpoints.

Prereq:  python examples/cli.py serve --config examples/guard_config.json
Then:    python examples/agent_client.py
"""
import sys, os, json, urllib.request
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

BASE = "http://127.0.0.1:8080"
MERCHANT = "0xMerchant1111111111111111111111111111111111"


def _post(path, payload):
    req = urllib.request.Request(
        BASE + path, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read().decode())


def ask_guard(action_type, target, method=None, params=None, cost=0.0):
    return _post("/guard", {
        "action_type": action_type, "target": target,
        "method": method, "params": params or {}, "cost": cost,
    })


def main():
    # The agent's plan. It proposes; the guard disposes.
    intents = [
        ("api_call", "https://api.research.example/v1/search",
         "POST", {"query": "agent safety"}, 0.50),
        ("api_call", "https://api.research.example/v1/admin/config",
         "POST", {"query": "x"}, 0.50),          # forbidden token -> block
        ("payment", MERCHANT, "x402", {"resource": "weather"}, 0.10),
        ("payment", "0xEvil9999999999999999999999999999999999",
         "x402", {"resource": "weather"}, 0.10),  # forbidden recipient
    ]

    print("AGENT running through the guard (guard decides, agent obeys)\n")
    for action_type, target, method, params, cost in intents:
        d = ask_guard(action_type, target, method, params, cost)
        decision = "ALLOWED" if d["allowed"] else "BLOCKED"
        print(f"  intent: {action_type} {method or ''} {target}")
        print(f"    guard -> {decision}"
              + (f"  ({d['block_reason']})" if d["block_reason"] else ""))
        # The agent ONLY proceeds on allow. On block/approval it stops.
        if d["allowed"]:
            print(f"    agent: proceeding with {action_type}")
        else:
            print(f"    agent: NOT executing (guard denied)")
        print()

    # Show the audit trail the guard kept
    print("GUARD AUDIT (every decision, immutable):")
    with urllib.request.urlopen(BASE + "/audit", timeout=10) as r:
        events = json.loads(r.read().decode()).get("events", [])
    for e in events[-6:]:
        print(f"  [{e['event_type']}] {e.get('data', {}).get('target', '')}")


if __name__ == "__main__":
    main()
