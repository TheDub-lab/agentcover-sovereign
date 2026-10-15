# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 Michael / TheDub-lab
"""Run the log receiver:  python -m safety_protocol.platform.receiver --db logs.db"""

from __future__ import annotations

import argparse
import os

from .server import serve


def main(argv=None):
    ap = argparse.ArgumentParser(description="safety-protocol log receiver")
    ap.add_argument("--db", default="receiver.db", help="SQLite database path")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--admin-key", default=os.environ.get("RECEIVER_ADMIN_KEY"),
                    help="admin bearer key (or RECEIVER_ADMIN_KEY env)")
    args = ap.parse_args(argv)
    serve(args.db, args.host, args.port, admin_key=args.admin_key)


if __name__ == "__main__":
    main()
