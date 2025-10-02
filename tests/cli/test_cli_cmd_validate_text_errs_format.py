import io
import sys
import types

from rbacx import cli


def test_cmd_validate_text_formats_errors_with_index_and_message(monkeypatch, capsys):
    def fake_validate_doc(doc, policyset=False):
        return [{"message": "bad", "policy_index": 1}]

    monkeypatch.setattr(cli, "_validate_doc", fake_validate_doc, raising=True)
    # Provide stdin for validate
    monkeypatch.setattr(sys, "stdin", io.StringIO('{"policies":[{"rules":[]}]}'), raising=True)
    ns = types.SimpleNamespace(policy=None, policyset=True, format="text")
    rc = cli.cmd_validate(ns)
    out = capsys.readouterr().out
    assert rc == cli.EXIT_SCHEMA_ERRORS
    assert "SCHEMA [policy_index=1]: bad" in out
