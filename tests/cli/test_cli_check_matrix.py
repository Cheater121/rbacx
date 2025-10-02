
import io
import json
import sys
import types
from rbacx import cli

def _ok_policy():
    return {"rules": []}

def test_cmd_check_ok_then_lint_no_issues(tmp_path, capsys, monkeypatch):
    # validate OK, lint OK
    monkeypatch.setattr(cli, "validate_policy", lambda doc: None, raising=True)
    monkeypatch.setattr(cli, "analyze_policy", lambda *a, **k: [], raising=True)

    p = tmp_path / "ok.json"
    p.write_text(json.dumps(_ok_policy()), encoding="utf-8")

    ns = types.SimpleNamespace(policy=str(p), policyset=False, strict=False, format="json")
    rc = cli.cmd_check(ns)
    out = capsys.readouterr().out.strip().splitlines()
    assert rc == cli.EXIT_OK
    assert out == ["[]", "[]"]

def test_cmd_check_ok_then_lint_issues_strict(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(cli, "validate_policy", lambda doc: None, raising=True)
    monkeypatch.setattr(cli, "analyze_policy", lambda *a, **k: [{"code": "X"}], raising=True)

    p = tmp_path / "ok.json"
    p.write_text(json.dumps(_ok_policy()), encoding="utf-8")

    ns = types.SimpleNamespace(policy=str(p), policyset=False, strict=True, format="text")
    rc = cli.cmd_check(ns)
    out = capsys.readouterr().out.strip().splitlines()
    assert rc == cli.EXIT_LINT_ERRORS
    # text mode: first line "OK", second line holds lint issues (one per line)
    assert out[0] == "OK"
    assert "X" in out[1]

def test_cmd_check_from_stdin(monkeypatch, capsys):
    # With buffering in cmd_check, stdin should work
    monkeypatch.setattr(cli, "validate_policy", lambda doc: None, raising=True)
    monkeypatch.setattr(cli, "analyze_policy", lambda *a, **k: [], raising=True)
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps({"rules": []})), raising=True)

    ns = types.SimpleNamespace(policy=None, policyset=False, strict=False, format="json")
    rc = cli.cmd_check(ns)
    out = capsys.readouterr().out.strip().splitlines()
    assert rc == cli.EXIT_OK
    assert out == ["[]", "[]"]
