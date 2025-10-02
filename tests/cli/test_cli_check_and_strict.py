import io
import json
import sys
import types
import pytest

from rbacx import cli


def _ok_policy():
    return {"rules": []}


def _lint_issue():
    return [{"code": "DEMO", "message": "demo issue"}]


def test_cmd_lint_strict_nonzero_on_issues(monkeypatch, capsys, tmp_path):
    # Stub linter to return a non-empty list → issues present
    monkeypatch.setattr(cli, "analyze_policy", lambda *a, **k: _lint_issue(), raising=True)

    p = tmp_path / "ok.json"
    p.write_text(json.dumps(_ok_policy()), encoding="utf-8")

    ns = types.SimpleNamespace(policy=str(p), policyset=False, strict=True, format="json")
    code = cli.cmd_lint(ns)
    out = capsys.readouterr().out.strip()

    assert json.loads(out) == _lint_issue()
    assert code == cli.EXIT_LINT_ERRORS


def test_cmd_lint_non_strict_zero_on_issues(monkeypatch, capsys, tmp_path):
    # Same issues, but strict disabled → exit 0
    monkeypatch.setattr(cli, "analyze_policy", lambda *a, **k: _lint_issue(), raising=True)

    p = tmp_path / "ok.json"
    p.write_text(json.dumps(_ok_policy()), encoding="utf-8")

    ns = types.SimpleNamespace(policy=str(p), policyset=False, strict=False, format="json")
    code = cli.cmd_lint(ns)

    assert code == cli.EXIT_OK


def test_cmd_check_returns_validation_error_first(monkeypatch, tmp_path):
    # Validation error should short-circuit and not call lint
    called = {"lint": False}

    def fake_validate_policy(doc):
        raise Exception("schema error")

    def fake_analyze_policy(doc, require_attrs=None):
        called["lint"] = True
        return []

    monkeypatch.setattr(cli, "validate_policy", fake_validate_policy, raising=True)
    monkeypatch.setattr(cli, "analyze_policy", fake_analyze_policy, raising=True)

    p = tmp_path / "bad.json"
    # malformed JSON would be raised by parse step; here pass valid JSON, but invalid per schema
    p.write_text(json.dumps({"rules": [{"id": "r", "effect": "permit", "actions": [], "resource": {"type": "doc"}}]}), encoding="utf-8")

    ns = types.SimpleNamespace(policy=str(p), policyset=False, strict=True, format="json")
    code = cli.cmd_check(ns)

    assert code == cli.EXIT_SCHEMA_ERRORS
    assert called["lint"] is False


def test_cmd_check_strict_applies_to_lint_only(monkeypatch, tmp_path, capsys):
    # Validation ok, lint has issues → with --strict should be EXIT_LINT_ERRORS
    monkeypatch.setattr(cli, "validate_policy", lambda doc: None, raising=True)
    monkeypatch.setattr(cli, "analyze_policy", lambda *a, **k: [{"code": "X"}], raising=True)

    p = tmp_path / "ok.json"
    p.write_text(json.dumps(_ok_policy()), encoding="utf-8")

    ns = types.SimpleNamespace(policy=str(p), policyset=False, strict=True, format="json")
    code = cli.cmd_check(ns)
    out = capsys.readouterr().out.strip()

    assert code == cli.EXIT_LINT_ERRORS
    assert out.startswith("[")  # lint printed JSON issues


def test_main_returns_code_instead_of_exiting(monkeypatch, capsys, tmp_path):
    # Smoke for main(): valid validate path should return 0 (no SystemExit)
    p = tmp_path / "ok.json"
    p.write_text(json.dumps(_ok_policy()), encoding="utf-8")

    rc = cli.main(["validate", "--policy", str(p), "--format", "text"])
    out = capsys.readouterr().out.strip()

    assert rc == cli.EXIT_OK
    assert out == "OK"

