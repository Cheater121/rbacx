import argparse, json
from rbacx.cli import build_parser, cmd_lint

def test_build_parser_has_subcommands():
    p = build_parser()
    assert any(a.dest=="command" for a in p._actions)

def test_cmd_lint_policyset_flag(tmp_path, capsys):
    data = {"rules":[{"id":"", "actions": [], "resource":{"type":"*"}}]}
    f = tmp_path/"p.json"
    f.write_text(json.dumps(data), encoding="utf-8")
    ns = argparse.Namespace(policy=str(f), require_attrs=None, policyset=True)
    cmd_lint(ns)
    out = capsys.readouterr().out
    assert out.strip().startswith("[")
