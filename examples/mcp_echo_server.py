#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Michael / TheDub-lab
"""A tiny, harmless MCP server used to demo the safety guard's MCP proxy.

It speaks newline-delimited JSON-RPC 2.0 on stdio (the MCP stdio transport) and
answers the handful of methods the demo exercises. It does NOT touch the
filesystem — every "file" is a canned string — so it is safe to run anywhere.

    python examples/mcp_echo_server.py

By itself it is not interesting. Put ``safety-guard mcp-proxy`` in front of it
(see ``examples/mcp_proxy_demo.py``) and its tools become gated: a ``tools/call``
that policy denies never reaches this process, and a tool that needs a human
sign-off is held until an operator approves it.
"""
from __future__ import annotations

import json
import sys

SERVER_INFO = {"name": "filesystem-demo", "version": "1.0.0"}

TOOLS = [
    {
        "name": "read_file",
        "description": "Read a file from the workspace.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
            "additionalProperties": False,
        },
    },
    {
        "name": "list_directory",
        "description": "List a directory.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
            "additionalProperties": False,
        },
    },
    {
        "name": "write_file",
        "description": "Write a file (mutates state).",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
            "required": ["path", "content"],
            "additionalProperties": False,
        },
    },
    {
        "name": "delete_everything",
        "description": "Irreversibly delete the whole workspace.",
        "inputSchema": {"type": "object", "properties": {}},
    },
]

RESOURCES = [
    {"uri": "file:///data/reports/q4.csv", "name": "q4", "mimeType": "text/csv"},
    {"uri": "file:///data/notes.txt", "name": "notes", "mimeType": "text/plain"},
]


def _result(msg_id, result):
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def _text_result(msg_id, text):
    return _result(msg_id, {"content": [{"type": "text", "text": text}], "isError": False})


def handle(msg: dict) -> dict | None:
    method = msg.get("method")
    msg_id = msg.get("id")

    if method == "initialize":
        return _result(msg_id, {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}, "resources": {}},
            "serverInfo": SERVER_INFO,
        })

    if method == "tools/list":
        return _result(msg_id, {"tools": TOOLS})

    if method == "tools/call":
        params = msg.get("params") or {}
        name = params.get("name")
        args = params.get("arguments") or {}
        if name == "read_file":
            return _text_result(msg_id, f"<contents of {args.get('path')}>")
        if name == "list_directory":
            return _text_result(msg_id, "q4.csv\nnotes.txt")
        if name == "write_file":
            n = len(args.get("content", ""))
            return _text_result(msg_id, f"wrote {n} bytes to {args.get('path')}")
        if name == "delete_everything":
            return _text_result(msg_id, "workspace deleted")
        return {"jsonrpc": "2.0", "id": msg_id,
                "error": {"code": -32602, "message": f"unknown tool {name!r}"}}

    if method == "resources/list":
        return _result(msg_id, {"resources": RESOURCES})

    if method == "resources/read":
        uri = (msg.get("params") or {}).get("uri")
        return _result(msg_id, {"contents": [
            {"uri": uri, "mimeType": "text/csv", "text": f"<contents of {uri}>"}]})

    # Notifications and unknown methods: notifications get no reply.
    if msg_id is None:
        return None
    return {"jsonrpc": "2.0", "id": msg_id,
            "error": {"code": -32601, "message": f"method not found: {method}"}}


def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        reply = handle(msg)
        if reply is not None:
            sys.stdout.write(json.dumps(reply, separators=(",", ":")) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
