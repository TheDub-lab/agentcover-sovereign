#!/usr/bin/env python3
"""
CLI for the safety guard — the surface a real agent (or its operator) uses.

Subcommands (all read the USER-CONTROLLED config; none let the agent
widen scope):
  serve    start the HTTP guard (fails closed if rules fail lint)
  check    ask the guard whether an intent is allowed  (--action/--target/...)
  pay      request a gated payment                       (--recipient/--usd)
  lint     lint the config ruleset and exit non-zero if too broad

Run:
  python examples/cli.py serve   --config examples/guard_config.json
  python examples/cli.py check   --config examples/guard_config.json \
        --action api_call --target https://api.research.example/v1/search \
        --method POST --params '{"query":"hi"}'
  python examples/cli.py pay     --config examples/guard_config.json \
        --recipient 0xMerchant1111111111111111111111111111111 --usd 0.10
  python examples/cli.py lint    --config examples/guard_config.json
"""
import sys, os, json, argparse
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from safety_protocol.guard_service import GuardService, serve as serve_http
from safety_protocol.scope_linter import lint_rules, lint_report, Severity


def load_cfg(path):
    with open(path) as f:
        return json.load(f)


def cmd_serve(args):
    # Delegate to the HTTP server entry (fails closed on lint via GuardService).
    serve_http(args.config, args.host, args.port)


def cmd_check(args):
    svc = GuardService(load_cfg(args.config))
    params = json.loads(args.params) if args.params else {}
    r = svc.guard(args.action, args.target, method=args.method,
                  params=params, cost=args.cost)
    print(json.dumps(r, indent=2))
    sys.exit(0 if r["allowed"] else 1)


def cmd_pay(args):
    svc = GuardService(load_cfg(args.config))
    r = svc.pay(args.recipient, args.usd, resource=args.resource)
    print(json.dumps(r, indent=2))
    sys.exit(0 if r["allowed"] else 1)


def cmd_lint(args):
    cfg = load_cfg(args.config)
    # Rebuild via the same path the guard uses, so lint + fail-closed match.
    from safety_protocol.guard_service import build_protocol_from_config
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


def main():
    ap = argparse.ArgumentParser(prog="safety-guard", description="Safety guard CLI")
    sub = ap.add_subparsers(dest="cmd", required=True)

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
    c.set_defaults(func=cmd_check)

    p = sub.add_parser("pay", help="request a gated payment")
    p.add_argument("--config", required=True)
    p.add_argument("--recipient", required=True)
    p.add_argument("--usd", type=float, required=True)
    p.add_argument("--resource", default="weather")
    p.set_defaults(func=cmd_pay)

    l = sub.add_parser("lint", help="lint the config ruleset")
    l.add_argument("--config", required=True)
    l.set_defaults(func=cmd_lint)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
