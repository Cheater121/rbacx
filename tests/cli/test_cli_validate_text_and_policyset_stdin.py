import io
import json
import sys
import types
from rbacx import cli

def test_cmd_validate_text_policyset_from_stdin(monkeypatch, capsys):
    stdin_doc = {"policies": [{"rules": []}, {"rules": []}]}
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(stdin_doc)), raising=True)

    ns = types.SimpleNamespace(policy=None, policyset=True, format="text")
    rc = cli.cmd_validate(ns)
    out = capsys.readouterr().out.strip()

    assert rc == cli.EXIT_OK
    assert out == "OK"

