# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Michael / TheDub-lab
"""
MCP proxy — route every MCP tool call through the safety guard.

This is the "five-minute" integration: put the guard *between* an MCP client
(Claude Desktop, an agent host, another agent) and a real MCP server, and every
tool call the agent makes is evaluated before it reaches the server.

    MCP client  <--stdio-->  safety-guard mcp-proxy  <--stdio-->  MCP server

``tools/call``, ``resources/read`` and ``resources/subscribe`` are intercepted
(``mcp.gate_resources`` controls the resource pair; on by default).
``initialize``, ``tools/list``, ``prompts/*``, notifications and server-initiated
requests are forwarded untouched (the ``initialize`` response is annotated so the
client can see the guard is in the path). A denied call never reaches the
upstream server; the agent gets a normal MCP error (``isError: true``) carrying
the reason.

Policy mapping — each tool call becomes one guard action:

    action_type = "mcp_tool_call"   (configurable)
    target      = the tool name
    method      = "MCP"             (configurable)
    params      = the tool arguments
    cost        = mcp.cost_per_call (default 0 — set it to make budget bite)

Each resource read/subscribe becomes one guard action too:

    action_type = "mcp_resource_read" / "mcp_resource_subscribe"  (configurable)
    target      = the normalized resource URI
    method      = "MCP"
    params      = {"uri": <normalized URI>}
    cost        = mcp.cost_per_call

The URI is normalized before the rule is consulted (single percent-decode,
scheme/host lowercased, ``.``/``..`` collapsed with traversal rejected, scheme
must be allowlisted) so ``%2e%2e/`` cannot slip past a ``file:///data/reports/*``
rule. A URI that fails normalization is denied in every mode and never
forwarded.

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

The control endpoint is protected by an approver secret (generated at start,
printed or written to a 0600 file). ``POST /approve`` and ``GET /pending``
require it via ``X-Approver-Secret: <secret>`` or ``Authorization: Bearer
<secret>``; a request without it is rejected 401 and the attempt is written to
the audit chain. Binding to a non-loopback address without a secret is refused.

This module is stdlib-only: it speaks newline-delimited JSON-RPC 2.0, which is
the MCP stdio transport, so it adds no dependency to the SDK.
"""
from __future__ import annotations

import contextlib
import hmac
import json
import os
import secrets
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlsplit

from .config import build_protocol_from_config
from .core import ActionOutcome, ActionRequest
from .shipping import shipper_from_config

JSONRPC_ERROR = -32603
"""JSON-RPC internal-error code (used only for malformed control requests)."""

DEFAULT_URI_SCHEMES = ("file",)
"""Resource-URI schemes the proxy will normalize and forward by default."""

_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}

_RESOURCE_METHODS = ("resources/read", "resources/subscribe")


def _is_loopback(host: str) -> bool:
    h = (host or "").strip().lower()
    return h in _LOOPBACK_HOSTS or h.startswith("127.")


def normalize_resource_uri(
    uri, allowed_schemes=None
) -> tuple[str | None, str | None]:
    """Normalize an MCP resource URI for scope matching.

    Returns ``(normalized_uri, None)`` on success, or ``(None, reason)`` if the
    URI must be rejected. Rejection is a hard deny: a URI that does not
    normalize cleanly cannot be matched safely against an allowlist, so it is
    never forwarded — in enforce *or* shadow mode.

    Normalization:
      * must be a non-empty string containing ``://`` (hierarchical URI)
      * percent-decoded exactly ONCE; a residual ``%`` (double-encoding) is
        rejected, as are NUL/control characters
      * scheme and host are lowercased; for ``file://`` an empty host and
        ``localhost`` are treated as the same (local) host
      * ``.`` segments are dropped and ``..`` segments are collapsed; a ``..``
        that would escape the root is rejected (traversal)
      * the scheme must be in ``allowed_schemes`` (default ``["file"]``)

    Casing of the *path* is preserved here; matching is case-insensitive
    because ``target_matches`` lowercases both sides.
    """
    schemes = [s.lower() for s in (allowed_schemes or DEFAULT_URI_SCHEMES)]

    if not isinstance(uri, str) or not uri.strip():
        return None, "resource uri must be a non-empty string"

    raw = uri.strip()

    # Reject control characters before any decoding.
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in raw):
        return None, "resource uri contains control characters"

    # Single percent-decode, then forbid any residual '%' (double-encoding).
    decoded = unquote(raw)
    if "%" in decoded:
        return None, "resource uri uses double-encoded characters ('%')"

    if "://" not in decoded:
        return None, "resource uri is not a hierarchical URI (missing '://')"

    parts = urlsplit(decoded)
    scheme = parts.scheme.lower()
    if not scheme:
        return None, "resource uri has no scheme"
    if scheme not in schemes:
        return None, f"resource uri scheme '{scheme}' is not allowed {schemes}"

    netloc = parts.netloc.lower()
    if scheme == "file" and netloc in ("", "localhost"):
        netloc = ""

    path = parts.path or "/"
    trailing = path.endswith("/") and path != "/"
    segments = [s for s in path.split("/") if s not in ("", ".")]
    resolved: list[str] = []
    for seg in segments:
        if seg == "..":
            if not resolved:
                return None, "resource uri escapes its root ('..')"
            resolved.pop()
        else:
            resolved.append(seg)
    new_path = "/" + "/".join(resolved)
    if trailing and not new_path.endswith("/"):
        new_path += "/"

    return f"{scheme}://{netloc}{new_path}", None


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
        gate_resources: bool = True,
        resource_read_action_type: str = "mcp_resource_read",
        resource_subscribe_action_type: str = "mcp_resource_subscribe",
        allowed_uri_schemes: list[str] | None = None,
    ):
        self.protocol = protocol
        self.action_type = action_type
        self.method = method
        self.cost_per_call = float(cost_per_call or 0.0)
        self.server_name = server_name
        self.server_version = server_version or _sdk_version()
        self.gate_resources = bool(gate_resources)
        self.resource_read_action_type = resource_read_action_type
        self.resource_subscribe_action_type = resource_subscribe_action_type
        self.allowed_uri_schemes = list(
            allowed_uri_schemes or DEFAULT_URI_SCHEMES)
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

    def evaluate_resource(self, raw_uri, action_type) -> tuple[ActionRequest, object, str | None]:
        """Run one resource read/subscribe through the guard.

        Returns ``(request, result, normalized_uri)``. If the URI fails
        normalization the result is a hard block (recorded via
        ``protocol.block``) and ``normalized_uri`` is None.
        """
        normalized, err = normalize_resource_uri(raw_uri, self.allowed_uri_schemes)
        target = normalized if normalized is not None else str(raw_uri)
        request = ActionRequest(
            action_type=action_type,
            target=target,
            method=self.method,
            params={"uri": target},
            estimated_cost=self.cost_per_call,
        )
        if err:
            result = self.protocol.block(request, f"resource uri rejected: {err}")
            return request, result, None
        return request, self.protocol.execute(request), normalized

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

        if method in _RESOURCE_METHODS and has_id:
            if not self.gate_resources:
                # Explicitly ungated: forward untouched (config is loud about
                # this at startup and via the audit chain).
                to_upstream.append(self._forward(msg, "pass", method))
                return to_client, to_upstream
            params = msg.get("params") or {}
            action_type = (
                self.resource_read_action_type
                if method == "resources/read"
                else self.resource_subscribe_action_type
            )
            request, result, normalized = self.evaluate_resource(
                params.get("uri"), action_type)
            if result.outcome == ActionOutcome.ALLOWED and result.executed:
                out = msg
                if normalized is not None:
                    out = dict(msg)
                    out["params"] = {**params, "uri": normalized}
                to_upstream.append(self._forward(out, "pass", method))
            else:
                to_client.append(self._tool_error(msg["id"], request, result))
            return to_client, to_upstream

        # Everything else passes through (initialize, tools/list, prompts,
        # ping, notifications, …).
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
                "Blocked by safety guard: this request requires human "
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
    # When set, /pending and /approve require this secret. None = no auth
    # (loopback only, warned about at startup).
    secret: str | None = None

    def log_message(self, *args):  # silence the default stderr chatter
        pass

    def _reply(self, code: int, obj: dict) -> None:
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _supplied_secret(self) -> str:
        supplied = self.headers.get("X-Approver-Secret") or ""
        if not supplied:
            auth = self.headers.get("Authorization") or ""
            if auth.lower().startswith("bearer "):
                supplied = auth[7:].strip()
        return supplied

    def _authorized(self) -> bool:
        if not self.secret:
            return True
        return hmac.compare_digest(self._supplied_secret(), self.secret)

    def _reject_unauthorized(self) -> None:
        # An agent that tries to approve its own action is exactly the threat
        # the secret exists to stop — record the attempt in the audit chain.
        with contextlib.suppress(Exception):
            remote = self.client_address[0] if self.client_address else None
            self.proxy.protocol.audit.append(
                "approval_auth_failed", self.proxy.protocol.agent_id,
                {"path": self.path, "remote": remote,
                 "had_secret": bool(self._supplied_secret())})
        self._reply(401, {"error": "approver secret required"})

    def do_GET(self):  # noqa: N802 (http.server API)
        if self.path == "/health":
            self._reply(200, {"ok": True, "mode": self.proxy.protocol.mode})
        elif self.path == "/pending":
            if not self._authorized():
                self._reject_unauthorized()
                return
            self._reply(200, {"pending": self.proxy.protocol.get_pending_approvals()})
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
            if not self._authorized():
                self._reject_unauthorized()
                return
            token = body.get("token")
            approved = bool(body.get("approved", True))
            approver = body.get("approver") or self.approver
            if not token:
                self._reply(400, {"error": "missing token"})
                return
            ok = self.proxy.protocol.decide_approval(
                token, approved, approver=approver, reason=body.get("reason"),
                channel="control")
            self._reply(200 if ok else 404, {"ok": ok, "approved": approved})
        else:
            self._reply(404, {"error": "not found"})


def start_control_server(
    proxy: MCPProxy,
    host: str = "127.0.0.1",
    port: int = 8788,
    *,
    secret: str | None = None,
    require_secret: bool = True,
) -> ThreadingHTTPServer:
    """Start the approval control endpoint in a background thread.

    Refuses to bind to a non-loopback address without a secret; warns loudly if
    started on loopback with no secret (any local process could approve).
    """
    if secret is None and require_secret:
        if not _is_loopback(host):
            raise ValueError(
                f"refusing to bind the approval control endpoint to "
                f"non-loopback host {host!r} without an approver secret")
        print(
            "WARNING: approval control endpoint has no approver secret — any "
            "local process can approve actions. Pass an approver secret to "
            "require authentication.",
            file=sys.stderr,
        )
    handler = type("_BoundControlHandler", (_ControlHandler,),
                   {"proxy": proxy, "secret": secret})
    httpd = ThreadingHTTPServer((host, port), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def _write_secret_file(path: str, secret: str) -> None:
    """Write the approver secret to a file readable only by the owner."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, (secret + "\n").encode("utf-8"))
    finally:
        os.close(fd)
    with contextlib.suppress(OSError):
        os.chmod(path, 0o600)


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
    gate_resources = mcp.get("gate_resources", True)
    proxy = MCPProxy(
        protocol,
        action_type=mcp.get("action_type", "mcp_tool_call"),
        method=mcp.get("method", "MCP"),
        cost_per_call=mcp.get("cost_per_call", 0.0),
        server_name=mcp.get("server_name", "safety-protocol-guard"),
        gate_resources=gate_resources,
        resource_read_action_type=mcp.get(
            "resource_read_action_type", "mcp_resource_read"),
        resource_subscribe_action_type=mcp.get(
            "resource_subscribe_action_type", "mcp_resource_subscribe"),
        allowed_uri_schemes=mcp.get("allowed_uri_schemes"),
    )
    if not gate_resources:
        # Record in the audit chain that resource gating is off. The scope
        # linter also emits a loud (non-blocking) warning for this.
        protocol.audit.append("resources_ungated", protocol.agent_id, {
            "reason": "mcp.gate_resources=false",
        })
    return protocol, proxy, shipper, findings


def run_mcp_proxy(
    cfg: dict,
    upstream_argv: list[str],
    *,
    control_host: str = "127.0.0.1",
    control_port: int | None = 8788,
    start_shipper: bool = True,
    approver_secret: str | None = None,
    approver_secret_file: str | None = None,
    require_approver_secret: bool = True,
) -> None:
    """Build the guard, start the control endpoint, and pump stdio.

    When the control endpoint is enabled and no ``approver_secret`` is given,
    one is generated with ``secrets.token_urlsafe(32)`` and either written to
    ``approver_secret_file`` (mode 0600) or printed to stderr once. That secret
    is required on ``POST /approve`` and ``GET /pending``.
    """
    _, proxy, _, _ = proxy_from_config(cfg, start_shipper=start_shipper)
    if control_port:
        secret = approver_secret
        if secret is None and require_approver_secret:
            secret = secrets.token_urlsafe(32)
            if approver_secret_file:
                _write_secret_file(approver_secret_file, secret)
                print(f"approver secret written to {approver_secret_file}",
                      file=sys.stderr)
            else:
                print(f"approver secret: {secret}", file=sys.stderr)
                print("send it as 'X-Approver-Secret: <secret>' (or "
                      "'Authorization: Bearer <secret>') to POST /approve",
                      file=sys.stderr)
        with contextlib.suppress(OSError):
            start_control_server(
                proxy, control_host, control_port,
                secret=secret, require_secret=require_approver_secret)
    run_stdio(proxy, upstream_argv)
