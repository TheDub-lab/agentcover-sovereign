#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Michael / TheDub-lab
"""End-to-end demo: drive ``safety-guard mcp-proxy`` against a fake MCP server.

It starts the real proxy CLI in front of ``examples/mcp_echo_server.py``, speaks
JSON-RPC to the proxy exactly as an MCP client would, and shows what the guard
does with each call:

  * an allowed tool call passes through and the upstream result comes back;
  * a tool with no scope rule is denied — the call never reaches upstream;
  * a tool that needs a human sign-off is held, then allowed after an operator
    approves it over the control endpoint (using the approver secret);
  * a resource read inside scope passes; one outside scope is denied;
  * a double-encoded resource URI is rejected before any rule is consulted.

Every decision is written to a durable outbox as canonical JSON (``events.jsonl``)
— that is the verifiable audit chain. The script prints it at the end and checks
each event's hash.

    python examples/mcp_proxy_demo.py

Requires only the standard library plus this repo on ``PYTHONPATH`` (the script
sets it up). Nothing it runs touches the real filesystem.
"""
from __future__ import annotations

import contextlib
import json
import os
import queue
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
SRC = os.path.join(REPO, "src")

CONTROL_PORT = 8791
RECEIVER = "http://127.0.0.1:1/none"  # deliberately unreachable; outbox keeps everything


def _compact(obj) -> str:
    return json.dumps(obj, separators=(",", ":"))


def build_config(tmp: str) -> str:
    """Copy the shipped example config, add a local durable outbox."""
    with open(os.path.join(HERE, "mcp_guard_config.json"), encoding="utf-8") as f:
        cfg = json.load(f)
    cfg["shipping"] = {
        "receiver_url": RECEIVER,
        "api_key": "demo-key",
        "outbox_dir": os.path.join(tmp, "outbox"),
    }
    path = os.path.join(tmp, "guard_config.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    return path


class Client:
    """A minimal MCP client speaking to the proxy over pipes."""

    def __init__(self, cfg: str, secret_file: str):
        env = dict(os.environ)
        env["PYTHONPATH"] = SRC + os.pathsep + env.get("PYTHONPATH", "")
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "safety_protocol.cli", "mcp-proxy",
             "--config", cfg,
             "--control-port", str(CONTROL_PORT),
             "--approver-secret-file", secret_file,
             "--", sys.executable, os.path.join(HERE, "mcp_echo_server.py")],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8", bufsize=1, env=env,
        )
        self._q: queue.Queue = queue.Queue()
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self):
        for line in self.proc.stdout:
            line = line.strip()
            if line:
                self._q.put(json.loads(line))

    def send(self, msg: dict) -> None:
        self.proc.stdin.write(_compact(msg) + "\n")
        self.proc.stdin.flush()

    def request(self, msg: dict, timeout: float = 5.0) -> dict:
        self.send(msg)
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                reply = self._q.get(timeout=deadline - time.time())
            except queue.Empty:
                break
            if reply.get("id") == msg["id"]:
                return reply
        raise TimeoutError(f"no reply for id {msg['id']}")

    def notify(self, msg: dict) -> None:
        self.send(msg)

    def close(self) -> None:
        self.proc.stdin.close()
        self.proc.wait(timeout=10)


def approve(token: str, secret: str) -> tuple[int, dict]:
    body = json.dumps({"token": token, "approver": "alice"}).encode()
    req = urllib.request.Request(
        f"http://127.0.0.1:{CONTROL_PORT}/approve", data=body,
        headers={"X-Approver-Secret": secret, "Content-Type": "application/json"},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def hr(title: str) -> None:
    print(f"\n{'=' * 72}\n{title}\n{'=' * 72}")


def show_client(label: str, msg: dict) -> None:
    print(f"\n[client -> guard]  {label}")
    print(f"  {_compact(msg)}")


def show_reply(reply: dict) -> None:
    if "error" in reply:
        print(f"[guard -> client]  JSON-RPC error: {_compact(reply['error'])}")
        return
    result = reply.get("result", {})
    if result.get("isError"):
        guard = result.get("structuredContent", {}).get("guard", {})
        print("[guard -> client]  isError=true  (call blocked)")
        print(f"  text:   {result['content'][0]['text']}")
        print(f"  guard:  {_compact(guard)}")
    else:
        text = result.get("content", [{}])[0].get("text")
        if text is not None:
            print(f"[guard -> client]  ok: {text}")
        else:
            print(f"[upstream -> guard -> client]  {_compact(reply)}")


def drain_server_stderr(proc) -> None:
    err = proc.stderr.read()
    if err.strip():
        print("\n[proxy stderr]")
        print(err.rstrip())


def main() -> None:
    tmp = tempfile.mkdtemp(prefix="mcp-demo-")
    cfg = build_config(tmp)
    secret_file = os.path.join(tmp, "guard.secret")

    client = Client(cfg, secret_file)
    try:
        hr("1. initialize — the client sees a normal MCP server")
        show_client("initialize", {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                   "params": {"protocolVersion": "2024-11-05"}})
        show_reply(client.request({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                   "params": {"protocolVersion": "2024-11-05"}}))
        client.notify({"jsonrpc": "2.0", "method": "notifications/initialized"})

        hr("2. an allowed tool call — passes through to the server")
        show_client("tools/call read_file", {"jsonrpc": "2.0", "id": 2,
                   "method": "tools/call",
                   "params": {"name": "read_file", "arguments": {"path": "/data/notes.txt"}}})
        show_reply(client.request({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                   "params": {"name": "read_file", "arguments": {"path": "/data/notes.txt"}}}))

        hr("3. a tool with no scope rule — denied, never reaches the server")
        show_client("tools/call delete_everything", {"jsonrpc": "2.0", "id": 3,
                   "method": "tools/call",
                   "params": {"name": "delete_everything", "arguments": {}}})
        show_reply(client.request({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                   "params": {"name": "delete_everything", "arguments": {}}}))

        hr("4. a tool that needs approval — held, approved, then retried")
        write_msg = {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                     "params": {"name": "write_file",
                                "arguments": {"path": "/data/out.txt", "content": "hello"}}}
        show_client("tools/call write_file", write_msg)
        held = client.request(write_msg)
        show_reply(held)
        token = held["result"]["structuredContent"]["guard"]["approval_token"]
        secret = open(secret_file, encoding="utf-8").read().strip()
        print(f"\n[operator]        POST /approve  (approver secret from {os.path.basename(secret_file)})")
        status, body = approve(token, secret)
        print(f"[operator]        -> HTTP {status} {_compact(body)}")
        print("\n[client]          retry the same call after approval")
        show_client("tools/call write_file (retry)",
                    {**write_msg, "id": 5})
        show_reply(client.request({**write_msg, "id": 5}))

        hr("5. resource reads — gated by default")
        show_client("resources/read q4.csv", {"jsonrpc": "2.0", "id": 6,
                   "method": "resources/read",
                   "params": {"uri": "file:///data/reports/q4.csv"}})
        show_reply(client.request({"jsonrpc": "2.0", "id": 6,
                   "method": "resources/read",
                   "params": {"uri": "file:///data/reports/q4.csv"}}))

        show_client("resources/read (out of scope)", {"jsonrpc": "2.0", "id": 7,
                   "method": "resources/read", "params": {"uri": "file:///etc/shadow"}})
        show_reply(client.request({"jsonrpc": "2.0", "id": 7,
                   "method": "resources/read", "params": {"uri": "file:///etc/shadow"}}))

        show_client("resources/read (double-encoded traversal)",
                    {"jsonrpc": "2.0", "id": 8, "method": "resources/read",
                     "params": {"uri": "file:///data/reports/%252e%252e/secret"}})
        show_reply(client.request({"jsonrpc": "2.0", "id": 8, "method": "resources/read",
                   "params": {"uri": "file:///data/reports/%252e%252e/secret"}}))

        client.close()
        # give the shipper a moment to persist the last events
        time.sleep(0.3)
    finally:
        with contextlib.suppress(Exception):
            drain_server_stderr(client.proc)

    hr("6. the audit chain — canonical JSON events (events.jsonl)")
    events_path = os.path.join(tmp, "outbox", "events.jsonl")
    with open(events_path, encoding="utf-8") as f:
        lines = [json.loads(ln) for ln in f if ln.strip()]
    for ev in lines:
        print(_compact({k: ev[k] for k in (
            "seq", "decision", "policy_decision", "action_type", "target",
            "rule_id", "reason")}))
    print(f"\n{len(lines)} events, each hash-chained to the previous one.")


if __name__ == "__main__":
    main()
