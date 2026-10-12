"""Tests for the ``safety-guard`` CLI."""
import json

import pytest

from safety_protocol.cli import main


def _write_default(tmp_path):
    out = tmp_path / "guard_config.json"
    main(["init", "--out", str(out)])
    return out


def test_init_writes_config(tmp_path):
    out = _write_default(tmp_path)
    assert out.is_file()
    cfg = json.loads(out.read_text(encoding="utf-8"))
    assert cfg["scope_rules"]


def test_init_refuses_overwrite_without_force(tmp_path):
    out = tmp_path / "guard_config.json"
    out.write_text("{}", encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        main(["init", "--out", str(out)])
    assert exc.value.code == 1

    main(["init", "--out", str(out), "--force"])
    assert "scope_rules" in out.read_text(encoding="utf-8")


def test_lint_default_config_is_clean(tmp_path):
    out = _write_default(tmp_path)
    with pytest.raises(SystemExit) as exc:
        main(["lint", "--config", str(out)])
    assert exc.value.code == 0


def test_check_allows_in_scope_action(tmp_path):
    out = _write_default(tmp_path)
    with pytest.raises(SystemExit) as exc:
        main([
            "check", "--config", str(out),
            "--action", "api_call",
            "--target", "https://api.research.example/v1/search",
            "--method", "POST",
            "--params", '{"query": "hi"}',
        ])
    assert exc.value.code == 0


def test_check_blocks_out_of_scope_action(tmp_path):
    out = _write_default(tmp_path)
    with pytest.raises(SystemExit) as exc:
        main([
            "check", "--config", str(out),
            "--action", "access_bank",
            "--target", "bank_account",
        ])
    assert exc.value.code == 1


def test_check_blocks_forbidden_target(tmp_path):
    out = _write_default(tmp_path)
    with pytest.raises(SystemExit) as exc:
        main([
            "check", "--config", str(out),
            "--action", "api_call",
            "--target", "https://api.research.example/v1/admin",
            "--method", "POST",
            "--params", '{"query": "hi"}',
        ])
    assert exc.value.code == 1
