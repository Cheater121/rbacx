
import json
import types
import pytest
from rbacx import cli

def _ok_policy():
    return {"rules": []}

def _issues():
    return [{"code": "X", "message": "issue"}]

@pytest.mark.parametrize("fmt", ["json", "text"])
def test_cmd_lint_no_issues_all_formats(tmp_path, capsys, monkeypatch, fmt):
    monkeypatch.setattr(cli, "analyze_policy", lambda *a, **k: [], raising=True)
    p = tmp_path / "ok.json"
    p.write_text(json.dumps(_ok_policy()), encoding="utf-8")
    ns = types.SimpleNamespace(policy=str(p), policyset=False, strict=False, format=fmt)
    rc = cli.cmd_lint(ns)
    out = capsys.readouterr().out
    assert rc == cli.EXIT_OK
    if fmt == "json":
        assert out.strip() == "[]"
    else:
        # text formatter prints nothing for empty issues
        assert out.strip() == ""

@pytest.mark.parametrize("fmt", ["json", "text"])
def test_cmd_lint_issues_strict_and_non_strict(tmp_path, capsys, monkeypatch, fmt):
    monkeypatch.setattr(cli, "analyze_policy", lambda *a, **k: _issues(), raising=True)
    p = tmp_path / "p.json"
    p.write_text(json.dumps(_ok_policy()), encoding="utf-8")

    # non-strict -> exit 0
    ns = types.SimpleNamespace(policy=str(p), policyset=False, strict=False, format=fmt)
    rc = cli.cmd_lint(ns)
    out = capsys.readouterr().out
    assert rc == cli.EXIT_OK
    assert out

    # strict -> exit 3
    ns2 = types.SimpleNamespace(policy=str(p), policyset=False, strict=True, format=fmt)
    rc2 = cli.cmd_lint(ns2)
    out2 = capsys.readouterr().out
    assert rc2 == cli.EXIT_LINT_ERRORS
    assert out2
