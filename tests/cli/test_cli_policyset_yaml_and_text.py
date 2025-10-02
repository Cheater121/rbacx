
import json
import types
import pytest
from rbacx import cli

yaml = pytest.importorskip("yaml")

def test_cmd_lint_policyset_yaml_ok(tmp_path, capsys):
    p = tmp_path / "ps.yaml"
    # YAML policy set with one valid policy
    p.write_text("policies:\n  - rules: []\n", encoding="utf-8")
    ns = types.SimpleNamespace(policy=str(p), policyset=True, strict=False, format="text")
    rc = cli.cmd_lint(ns)
    out = capsys.readouterr().out
    assert rc == cli.EXIT_OK
    assert out.strip() == ""

def test_cmd_validate_policyset_yaml_ok(tmp_path, capsys):
    p = tmp_path / "ps.yaml"
    p.write_text("policies:\n  - rules: []\n", encoding="utf-8")
    ns = types.SimpleNamespace(policy=str(p), policyset=True, format="json")
    rc = cli.cmd_validate(ns)
    out = capsys.readouterr().out.strip()
    assert rc == cli.EXIT_OK
    assert out == "[]"
