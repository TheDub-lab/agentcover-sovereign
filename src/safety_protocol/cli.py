#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Michael / TheDub-lab
"""
``safety-guard`` — the CLI developers use to run and lint the guard.

Subcommands (all read the USER-CONTROLLED config; none let the agent widen
scope):

  init     write a default, least-privilege config to disk
  serve    start the HTTP guard (fails closed if rules fail lint)
  check    ask the guard whether an intent is allowed  (--action/--target/...)
  pay      request a gated payment                       (--recipient/--usd)
  lint     lint the config ruleset and exit non-zero if too broad
  mcp-proxy  run an MCP server behind the guard (every tool call gated)

Run:
  safety-guard init    --out guard_config.json
  safety-guard serve   --config guard_config.json
  safety-guard check   --config guard_config.json \\
        --action api_call --target https://api.research.example/v1/search \\
        --method POST --params '{"query":"hi"}'
  safety-guard pay     --config guard_config.json \\
        --recipient 0xMerchant1111111111111111111111111111111 --usd 0.10
  safety-guard lint    --config guard_config.json
  safety-guard mcp-proxy --config guard_config.json -- \\
        npx -y @modelcontextprotocol/server-filesystem /data
"""
from __future__ import annotations

import argparse
import json
import sys
from importlib.resources import files

from safety_protocol.config import build_protocol_from_config
from safety_protocol.core import ActionOutcome, ActionRequest
from safety_protocol.payments import SafeSpendAgent, SimWallet
from safety_protocol.scope_linter import Severity, lint_report
from safety_protocol.shipping import shipper_from_config


def load_cfg(path):
    with open(path) as f:
        return json.load(f)


def _attach_shipper(cfg, protocol, ship):
    """Attach a log shipper for a one-shot CLI decision, if requested.

    Shipping happens for a one-shot command only when the config has a
    ``shipping`` block AND ``--ship`` is passed. The decision is emitted and
    flushed once (blocking) so a receipt comes back synchronously.
    """
    if not ship:
        return None
    shipper = shipper_from_config(cfg)
    if shipper is None:
        print("warning: --ship given but config has no 'shipping' block",
              file=sys.stderr)
        return None
    protocol.add_decision_sink(shipper.emit)
    return shipper


def cmd_init(args):
    """Write the packaged default (least-privilege) config to disk."""
    import os

    if os.path.exists(args.out) and not args.force:
        print(f"refusing to overwrite existing file: {args.out} (use --force)")
        sys.exit(1)
    src = files("safety_protocol").joinpath("data/guard_config.json")
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(src.read_text(encoding="utf-8"))
    print(f"wrote default guard config to {args.out}")


def cmd_serve(args):
    # The HTTP guard service is part of the BSL platform layer, which is not
    # shipped in the MIT wheel. Import lazily so the free CLI works without it.
    try:
        from safety_protocol.platform.guard_service import serve as serve_http
    except ImportError:
        print(
            "safety-guard serve requires the platform layer (BUSL 1.1), which "
            "is not part of the MIT wheel.\nInstall the platform layer from "
            "the repo, or use a commercial license.",
            file=sys.stderr,
        )
        sys.exit(2)
    serve_http(args.config, args.host, args.port)


def cmd_check(args):
    cfg = load_cfg(args.config)
    protocol, _ = build_protocol_from_config(cfg)
    shipper = _attach_shipper(cfg, protocol, args.ship)
    params = json.loads(args.params) if args.params else {}
    res = protocol.execute(ActionRequest(
        action_type=args.action,
        target=args.target,
        method=args.method,
        estimated_cost=args.cost,
        params=params,
    ))
    out = {
        "outcome": res.outcome.value,
        "allowed": res.outcome == ActionOutcome.ALLOWED,
        "block_reason": res.block_reason,
        "requires_approval_for": res.requires_approval_for,
        "request_id": res.request_id,
    }
    if shipper is not None:
        receipt = shipper.flush_once()
        out["shipped"] = receipt is not None
        out["receipt"] = receipt
    print(json.dumps(out, indent=2))
    sys.exit(0 if out["allowed"] else 1)


def cmd_pay(args):
    cfg = load_cfg(args.config)
    protocol, _ = build_protocol_from_config(cfg)
    shipper = _attach_shipper(cfg, protocol, args.ship)
    agent = SafeSpendAgent(protocol=protocol, wallet=SimWallet())
    r = agent.direct_pay(args.recipient, args.usd, resource=args.resource)
    out = {
        "outcome": r.outcome,
        "allowed": r.outcome in ("paid", "pending_approval"),
        "block_reason": r.reason,
        "approval_token": r.approval_token,
        "signed": bool(r.envelope),
    }
    if shipper is not None:
        receipt = shipper.flush_once()
        out["shipped"] = receipt is not None
        out["receipt"] = receipt
    print(json.dumps(out, indent=2))
    sys.exit(0 if out["allowed"] else 1)


def cmd_mcp_proxy(args):
    """Run an upstream MCP server behind the guard over stdio."""
    cfg = load_cfg(args.config)
    upstream = list(args.upstream or [])
    if upstream and upstream[0] == "--":
        upstream = upstream[1:]
    if not upstream:
        print(
            "error: no upstream MCP command given.\n"
            "usage: safety-guard mcp-proxy --config guard_config.json -- "
            "<mcp-server-cmd> [args...]",
            file=sys.stderr,
        )
        sys.exit(2)
    from safety_protocol.mcp_proxy import run_mcp_proxy

    run_mcp_proxy(
        cfg,
        upstream,
        control_host=args.control_host,
        control_port=None if args.no_control else args.control_port,
    )


def cmd_lint(args):
    cfg = load_cfg(args.config)
    # Rebuild via the same path the guard uses, so lint + fail-closed match.
    try:
        _, findings = build_protocol_from_config(cfg)
    except SystemExit as e:
        # fail-closed: broad rules -> non-zero exit
        print(str(e))
        sys.exit(1)
    print(lint_report(findings))
    blocking = [f for f in findings
                if f.severity in (Severity.ERROR, Severity.WARN)]
    sys.exit(1 if blocking else 0)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="safety-guard", description="Safety guard CLI")
    sub = ap.add_subparsers(dest="cmd", required=True)

    i = sub.add_parser("init", help="write a default guard config")
    i.add_argument("--out", default="guard_config.json")
    i.add_argument("--force", action="store_true", help="overwrite if it exists")
    i.set_defaults(func=cmd_init)

    s = sub.add_parser("serve", help="start the HTTP guard")
    s.add_argument("--config", required=True)
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8080)
    s.set_defaults(func=cmd_serve)

    c = sub.add_parser("check", help="check if an intent is allowed")
    c.add_argument("--config", required=True)
    c.add_argument("--action", required=True)
    c.add_argument("--target", required=True)
    c.add_argument("--method")
    c.add_argument("--params", default="")
    c.add_argument("--cost", type=float, default=0.0)
    c.add_argument("--ship", action="store_true",
                   help="ship this decision to the configured receiver")
    c.set_defaults(func=cmd_check)

    p = sub.add_parser("pay", help="request a gated payment")
    p.add_argument("--config", required=True)
    p.add_argument("--recipient", required=True)
    p.add_argument("--usd", type=float, required=True)
    p.add_argument("--resource", default="weather")
    p.add_argument("--ship", action="store_true",
                   help="ship this decision to the configured receiver")
    p.set_defaults(func=cmd_pay)

    lint_p = sub.add_parser("lint", help="lint the config ruleset")
    lint_p.add_argument("--config", required=True)
    lint_p.set_defaults(func=cmd_lint)

    m = sub.add_parser(
        "mcp-proxy",
        help="run an MCP server behind the guard (every tool call gated)")
    m.add_argument("--config", required=True)
    m.add_argument("--control-host", default="127.0.0.1")
    m.add_argument("--control-port", type=int, default=8788,
                   help="localhost port for the approval control endpoint")
    m.add_argument("--no-control", action="store_true",
                   help="disable the local approval control endpoint")
    m.add_argument("upstream", nargs=argparse.REMAINDER,
                   help="-- <mcp-server-cmd> [args...]")
    m.set_defaults(func=cmd_mcp_proxy)

    args = ap.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
