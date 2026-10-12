"""Tests for the packaged ``safety_protocol`` installation surface."""
from importlib.resources import files

import safety_protocol


def test_version_is_set():
    assert safety_protocol.__version__
    assert safety_protocol.__version__.count(".") >= 1


def test_public_api_exports():
    for name in (
        "SafetyProtocol",
        "BoundAgent",
        "ScopeRule",
        "AuditTrail",
        "Monitor",
        "GuardService",
        "lint_rules",
        "ReferenceDeployment",
        "SafeSpendAgent",
    ):
        assert hasattr(safety_protocol, name), name


def test_default_config_is_packaged():
    cfg = files("safety_protocol").joinpath("data/guard_config.json")
    assert cfg.is_file()
    assert "scope_rules" in cfg.read_text(encoding="utf-8")


def test_cli_entrypoint_is_callable():
    from safety_protocol.cli import main

    assert callable(main)
