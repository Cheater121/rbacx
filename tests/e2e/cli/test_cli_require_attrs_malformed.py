
import argparse
from rbacx.cli import _parse_require_attrs, cmd_lint
import json
import pytest
import tempfile
import os

def test_parse_require_attrs_malformed():
    s = " ; ; : , , ;subject: id,, ;resource: , type ;  "
    parsed = _parse_require_attrs(s)
    # should not throw, and should keep only valid tokens
    assert parsed.get("subject") == ["id"]
    assert parsed.get("resource") == ["type"]

def test_cmd_lint_with_require_attrs_and_policy(tmp_path, capsys):
    policy_path = tmp_path / "p.json"
    policy_path.write_text(json.dumps({"rules":[]}), encoding="utf-8")
    ns = argparse.Namespace(policy=str(policy_path), require_attrs="subject:id;resource:type", policyset=False)
    cmd_lint(ns)
    out = capsys.readouterr().out.strip()
    assert out.startswith("[")  # JSON list
