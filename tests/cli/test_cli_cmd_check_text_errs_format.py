import io
import sys
import types

from rbacx import cli


def test_cmd_check_text_formats_errors_with_index_and_message(monkeypatch, capsys):
    def fake_validate_doc(doc, policyset=False):
        return [{"message": "oops", "policy_index": 3}]

    monkeypatch.setattr(cli, "_validate_doc", fake_validate_doc, raising=True)
    # Provide stdin for the initial document load
    monkeypatch.setattr(sys, "stdin", io.StringIO('{"policies": [{"rules": []}]}'), raising=True)

    ns = types.SimpleNamespace(policy=None, policyset=True, strict=False, format="text")
    rc = cli.cmd_check(ns)
    out = capsys.readouterr().out.strip()
    assert rc == cli.EXIT_SCHEMA_ERRORS
    assert out == "SCHEMA [policy_index=3]: oops"
