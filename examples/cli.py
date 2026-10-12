#!/usr/bin/env python3
"""
Thin shim: the CLI now ships inside the package as ``safety_protocol.cli``.

Prefer the installed console script:
    safety-guard serve --config examples/guard_config.json

This file remains so the checkout command still works:
    python examples/cli.py serve --config examples/guard_config.json
"""
import os
import sys

# Allow running from a source checkout without installing the package.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from safety_protocol.cli import main  # noqa: E402

if __name__ == "__main__":
    main()
