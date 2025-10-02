
import io
import json
import sys
import types
import pytest
from rbacx import cli

def test_cmd_lint_reads_policy_from_stdin_text(monkeypatch, capsys):
    # stdin single-policy
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps({"rules": []})), raising=True)
    # no format provided in ns -> default json
    ns = types.SimpleNamespace(policy=None, policyset=False, strict=False)
    rc = cli.cmd_lint(ns)
    out = capsys.readouterr().out
    assert rc == cli.EXIT_OK
    assert out.strip() == "[]"

def test_cmd_lint_reads_policyset_from_stdin_text(monkeypatch, capsys):
    doc = {"policies": [{"rules": []}]}
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(doc)), raising=True)
    # text format to exercise text printer
    ns = types.SimpleNamespace(policy=None, policyset=True, strict=False, format="text")
    rc = cli.cmd_lint(ns)
    out = capsys.readouterr().out
    assert rc == cli.EXIT_OK
    # policy set with no issues -> empty text output
    assert out.strip() == ""
