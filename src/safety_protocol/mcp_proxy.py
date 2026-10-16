# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Michael / TheDub-lab
"""
MCP proxy — route every MCP tool call through the safety guard.

This is the "five-minute" integration: put the guard *between* an MCP client
(Claude Desktop, an agent host, another agent) and a real MCP server, and every
tool call the agent makes is evaluated before it reaches the server.

    MCP client  <--stdio-->  safety-guard mcp-proxy  <--stdio-->  MCP server

Only ``tool/call`` is intercepted. ``initialize``, ``tools/list``,
``resources/*``, ``prompts/*``, notifications and server-initiated requests are
forwarded untouched (the ``initialize`` response is annotated so the client can
see the guard is in the path). A denied call never reaches the upstream server;
the agent gets a normal MCP tool error (``isError: true``) carrying the reason.

Policy mapping — each tool call becomes one guard action:

    action_type = "mcp_tool_call"   (configurable)
    target      = the tool name
    method      = "MCP"             (configurable)
    params      = the tool arguments
    cost        = mcp.cost_per_call (default 0 — set it to make budget bite)

A scope rule that permits an MCP tool therefore looks like:

    {
      "id": "mcp-read",
      "action_type": "mcp_tool_call",
      "allowed_targets": ["read_file"],
      "match": "exact",
      "methods": ["MCP"],
      "param_schema": {"required": ["path"],
                       "properties": {"path": {"type": "string"}},
                       "additional_properties": false},
      "requires_approval": false
    }

Approvals: a call whose rule sets ``requires_approval`` (or costs at/over the
approval threshold) is held. The agent gets an error naming the approval token;
an operator approves it out of band and the agent retries. Approvals are
decided over a localhost-only control endpoint (``GET /pending``,
``POST /approve``) or in-process via ``SafetyProtocol.decide_approval``.

This module is stdlib-only: it speaks newline-delimited JSON-RPC 2.0, which is
the MCP stdio transport, so it adds no dependency to the SDK.
"""
from __future__ import annotations

import contextlib
import json
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .config import build_protocol_from_config
from .core import ActionOutcome, ActionRequest
from .shipping import shipper_from_config

JSONRPC_ERROR = -32603
"""JSON-RPC internal-error code (used only for malformed control requests)."""


def _sdk_version() -> str:
    try:
        from importlib.metadata import version as _v

        return _v("safety-protocol")
    except Exception:  # pragma: no cover - source checkout
        return "0.0.0+source"


class MCPProxy:
    """Evaluates MCP ``tools/call`` messages against a ``SafetyProtocol``.

    The class is transport-free and synchronous: feed it decoded JSON-RPC
    messages, get back the messages to hand to the client and/or upstream
    server. ``run_stdio`` wires it to real stdin/stdout/subprocess pipes.
    """

    def __init__(
        self,
        protocol,
        *,
        action_type: str = "mcp_tool_call",
        method: str = "MCP",
        cost_per_call: float = 0.0,
        server_name: str = "safety-protocol-guard",
        server_version: str | None = None,
    ):
        self.protocol = protocol
        self.action_type = action_type
        self.method = method
        self.cost_per_call = float(cost_per_call or 0.0)
        self.server_name = server_name
        self.server_version = server_version or _sdk_version()
        self._seq = 0
        # proxy_id -> (kind, original client id) for client-originated requests
        self._up: dict[str, tuple[str, object]] = {}
        # proxy_id -> original upstream id for server-originated requests
        self._down: dict[str, object] = {}
        # proxy_id -> method, so responses can be post-processed
        self._method_of: dict[str, str] = {}

    # -- id bookkeeping ---------------------------------------------------

    def _new_id(self) -> str:
        self._seq += 1
        return f"sp-{self._seq}"

    def _forward(self, msg: dict, kind: str, method: str) -> dict:
        proxy_id = self._new_id()
        self._up[proxy_id] = (kind, msg.get("id"))
        self._method_of[proxy_id] = method
        out = dict(msg)
        out["id"] = proxy_id
        return out

    # -- policy -----------------------------------------------------------

    def evaluate(self, tool_name, arguments) -> tuple[ActionRequest, object]:
        """Run one tool call through the guard. Returns (request, result)."""
        request = ActionRequest(
            action_type=self.action_type,
            target=str(tool_name),
            method=self.method,
            params=dict(arguments) if isinstance(arguments, dict) else {},
            estimated_cost=self.cost_per_call,
        )
        return request, self.protocol.execute(request)

    # -- client -> upstream ----------------------------------------------

    def handle_client_message(self, msg) -> tuple[list[dict], list[dict]]:
        """Process one message from the MCP client.

        Returns ``(to_client, to_upstream)`` — decoded messages to write to the
        client and to the upstream server, respectively.
        """
        to_client: list[dict] = []
        to_upstream: list[dict] = []
        if not isinstance(msg, dict):
            return to_client, to_upstream

        method = msg.get("method")
        has_id = "id" in msg

        # A response from the client to a server-initiated request.
        if method is None:
            out = self._client_response(msg)
            if out is not None:
                to_upstream.append(out)
            return to_client, to_upstream

        if method == "tools/call" and has_id:
            params = msg.get("params") or {}
            request, result = self.evaluate(
                params.get("name"), params.get("arguments"))
            if result.outcome == ActionOutcome.ALLOWED and result.executed:
                to_upstream.append(self._forward(msg, "call", method))
            else:
                to_client.append(self._tool_error(msg["id"], request, result))
            return to_client, to_upstream

        # Everything else passes through (initialize, tools/list, resources,
        # prompts, ping, notifications, …).
        if has_id:
            to_upstream.append(self._forward(msg, "pass", method))
        else:
            to_upstream.append(msg)
        return to_client, to_upstream

    def _client_response(self, msg: dict) -> dict | None:
        pid = msg.get("id")
        if pid in self._down:
            out = dict(msg)
            out["id"] = self._down.pop(pid)
            return out
        return dict(msg)

    # -- upstream -> client ----------------------------------------------

    def handle_upstream_message(self, msg) -> list[dict]:
        """Process one message from the upstream server. Returns client msgs."""
        if not isinstance(msg, dict):
            return []
        method = msg.get("method")

        # Response to a client-originated request.
        if method is None and "id" in msg:
            pid = msg.get("id")
            kind, original = self._up.pop(pid, (None, pid))
            req_method = self._method_of.pop(pid, None)
            out = dict(msg)
            out["id"] = original
            if kind == "pass" and req_method == "initialize":
                out = self._patch_initialize(out)
            return [out]

        # Server-initiated request — rewrite the id so it cannot collide with a
        # client id, and remember the original to map the client's reply back.
        if method is not None and "id" in msg:
            proxy_id = self._new_id()
            self._down[proxy_id] = msg["id"]
            out = dict(msg)
            out["id"] = proxy_id
            return [out]

        # Notification.
        return [dict(msg)]

    def _patch_initialize(self, msg: dict) -> dict:
        result = msg.get("result")
        if not isinstance(result, dict):
            return msg
        result = dict(result)
        info = dict(result.get("serverInfo") or {})
        upstream = info.get("name")
        info["name"] = self.server_name
        info["version"] = self.server_version
        if upstream:
            info["upstream"] = upstream
        result["serverInfo"] = info
        out = dict(msg)
        out["result"] = result
        return out

    def _tool_error(self, client_id, request, result) -> dict:
        if result.outcome == ActionOutcome.PENDING_APPROVAL:
            token = result.requires_approval_for
            kind = "approval_required"
            text = (
                "Blocked by safety guard: this tool call requires human "
                f"approval (token {token}). An operator must approve it, then "
                "the call can be retried."
            )
        else:
            kind = "denied"
            text = f"Blocked by safety guard: {result.block_reason}"
        return {
            "jsonrpc": "2.0",
            "id": client_id,
            "result": {
                "content": [{"type": "text", "text": text}],
                "isError": True,
                "structuredContent": {
                    "guard": {
                        "kind": kind,
                        "decision": result.outcome.value,
                        "policy_decision": result.execution_log.get(
                            "policy_outcome"),
                        "rule_id": result.execution_log.get("rule_id"),
                        "request_id": result.request_id,
                        "approval_token": result.requires_approval_for,
                    }
                },
            },
        }


# ---------------------------------------------------------------------------
# stdio transport
# ---------------------------------------------------------------------------


def run_stdio(
    proxy: MCPProxy,
    upstream_argv: list[str],
    *,
    client_in=None,
    client_out=None,
) -> None:
    """Pump newline-delimited JSON-RPC between client, guard and upstream.

    Blocks until the client closes stdin, then tears the upstream down.
    """
    client_in = client_in if client_in is not None else sys.stdin
    client_out = client_out if client_out is not None else sys.stdout

    proc = subprocess.Popen(
        upstream_argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        bufsize=1,
    )
    write_lock = threading.Lock()

    def send(stream, obj: dict) -> None:
        with write_lock:
            stream.write(json.dumps(obj, separators=(",", ":")) + "\n")
            stream.flush()

    def pump_upstream() -> None:
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            with contextlib.suppress(json.JSONDecodeError):
                for m in proxy.handle_upstream_message(json.loads(line)):
                    send(client_out, m)

    reader = threading.Thread(target=pump_upstream, daemon=True)
    reader.start()
    try:
        for line in client_in:
            line = line.strip()
            if not line:
                continue
            with contextlib.suppress(json.JSONDecodeError):
                msg = json.loads(line)
                to_client, to_upstream = proxy.handle_client_message(msg)
                for m in to_upstream:
                    send(proc.stdin, m)
                for m in to_client:
                    send(client_out, m)
    finally:
        with contextlib.suppress(Exception):
            proc.stdin.close()
        # Let upstream finish in-flight responses (stdin EOF is our shutdown
        # signal), then tear it down.
        reader.join(timeout=2.0)
        with contextlib.suppress(Exception):
            proc.terminate()
        with contextlib.suppress(Exception):
            proc.wait(timeout=5)


# ---------------------------------------------------------------------------
# approval control endpoint (localhost only)
# ---------------------------------------------------------------------------


class _ControlHandler(BaseHTTPRequestHandler):
    proxy: MCPProxy
    approver: str = "operator"

    def log_message(self, *args):  # silence the default stderr chatter
        pass

    def _reply(self, code: int, obj: dict) -> None:
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802 (http.server API)
        if self.path == "/pending":
            self._reply(200, {"pending": self.proxy.protocol.get_pending_approvals()})
        elif self.path == "/health":
            self._reply(200, {"ok": True, "mode": self.proxy.protocol.mode})
        else:
            self._reply(404, {"error": "not found"})

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            self._reply(400, {"error": "invalid json"})
            return
        if self.path == "/approve":
            token = body.get("token")
            approved = bool(body.get("approved", True))
            approver = body.get("approver") or self.approver
            if not token:
                self._reply(400, {"error": "missing token"})
                return
            ok = self.proxy.protocol.decide_approval(
                token, approved, approver=approver, reason=body.get("reason"))
            self._reply(200 if ok else 404, {"ok": ok, "approved": approved})
        else:
            self._reply(404, {"error": "not found"})


def start_control_server(
    proxy: MCPProxy, host: str = "127.0.0.1", port: int = 8788
) -> ThreadingHTTPServer:
    """Start the approval control endpoint in a background thread."""
    handler = type("_BoundControlHandler", (_ControlHandler,), {"proxy": proxy})
    httpd = ThreadingHTTPServer((host, port), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


# ---------------------------------------------------------------------------
# config + entry point
# ---------------------------------------------------------------------------


def proxy_from_config(cfg: dict, *, start_shipper: bool = True):
    """Build ``(protocol, proxy, shipper, findings)`` from a guard config."""
    protocol, findings = build_protocol_from_config(cfg)
    shipper = shipper_from_config(cfg)
    if shipper is not None:
        protocol.add_decision_sink(shipper.emit)
        if start_shipper:
            shipper.start()
    mcp = cfg.get("mcp") or {}
    proxy = MCPProxy(
        protocol,
        action_type=mcp.get("action_type", "mcp_tool_call"),
        method=mcp.get("method", "MCP"),
        cost_per_call=mcp.get("cost_per_call", 0.0),
        server_name=mcp.get("server_name", "safety-protocol-guard"),
    )
    return protocol, proxy, shipper, findings


def run_mcp_proxy(
    cfg: dict,
    upstream_argv: list[str],
    *,
    control_host: str = "127.0.0.1",
    control_port: int | None = 8788,
    start_shipper: bool = True,
) -> None:
    """Build the guard, start the control endpoint, and pump stdio."""
    _, proxy, _, _ = proxy_from_config(cfg, start_shipper=start_shipper)
    if control_port:
        with contextlib.suppress(OSError):
            start_control_server(proxy, control_host, control_port)
    run_stdio(proxy, upstream_argv)
