import argparse
import json
import pytest
from rbacx.cli import build_parser, cmd_lint, _parse_require_attrs

def test_parse_require_attrs_various():
    assert _parse_require_attrs(None) == {}
    assert _parse_require_attrs("subject:id,org;resource:type") == {"subject":["id","org"],"resource":["type"]}

def test_cmd_lint_policyset_and_invalid_json(tmp_path, capsys):
    parser = build_parser()
    # valid empty rules
    p_ok = tmp_path / "pol.json"
    p_ok.write_text(json.dumps({"rules":[]}), encoding="utf-8")
    ns = argparse.Namespace(policy=str(p_ok), require_attrs="doc:id", policyset=True)
    cmd_lint(ns)
    out = capsys.readouterr().out
    assert out.strip().startswith("[")  # JSON list of issues

    # invalid JSON file should raise JSONDecodeError per json docs
    p_bad = tmp_path / "bad.json"
    p_bad.write_text("{not-json}", encoding="utf-8")
    ns_bad = argparse.Namespace(policy=str(p_bad), require_attrs=None, policyset=False)
    with pytest.raises(json.JSONDecodeError):
        cmd_lint(ns_bad)
