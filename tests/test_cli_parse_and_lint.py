
import json
import argparse
import pytest
from rbacx.cli import _parse_require_attrs, cmd_lint, build_parser

def test_parse_require_attrs():
    assert _parse_require_attrs(None) == {}
    s = "subject:id,org;resource:type"
    out = _parse_require_attrs(s)
    assert out == {"subject": ["id","org"], "resource": ["type"]}

def test_cmd_lint_prints_issues(tmp_path, capsys):
    pol = {"rules": [{"id": "", "actions": [], "resource": {"type": "*"}}]}
    p = tmp_path / "p.json"
    p.write_text(json.dumps(pol), encoding="utf-8")
    ns = argparse.Namespace(policy=str(p), require_attrs=None, policyset=False)
    cmd_lint(ns)
    stdout = capsys.readouterr().out
    data = json.loads(stdout)
    assert isinstance(data, list) and data
    assert any(i.get("code") in {"MISSING_ID", "EMPTY_ACTIONS", "BROAD_RESOURCE"} for i in data)

def test_build_parser_parses_lint_command():
    parser = build_parser()
    args = parser.parse_args(["lint", "--policy", "x.json", "--require-attrs", "doc:id"])
    assert args.command == "lint"
    assert args.policy == "x.json"
    assert getattr(args, "require_attrs", None) == "doc:id"
    assert hasattr(args, "func")
