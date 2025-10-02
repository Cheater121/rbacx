import io
import sys
import types

from rbacx import cli


def test_cmd_check_text_formats_errs_with_and_without_fields(monkeypatch, capsys):
    def fake_validate_doc(doc, policyset=False):
        return [
            {"message": "just-message"},  # no policy_index
            {"policy_index": 2},  # no message
        ]

    monkeypatch.setattr(cli, "_validate_doc", fake_validate_doc, raising=True)
    # Provide stdin for initial load (policy set not required for formatting branches)
    monkeypatch.setattr(sys, "stdin", io.StringIO('{"rules": []}'), raising=True)

    ns = types.SimpleNamespace(policy=None, policyset=False, strict=False, format="text")
    rc = cli.cmd_check(ns)
    out_lines = capsys.readouterr().out.strip().splitlines()

    assert rc == cli.EXIT_SCHEMA_ERRORS
    # First line should be the validate output; ensure both variants appear in the text
    assert "SCHEMA: just-message" in out_lines[0] or "SCHEMA [policy_index=2]" in out_lines[0]
    # If multiple lines printed (implementation prints all errors joined by \n), check both substrings
    txt = "\n".join(out_lines)
    assert "SCHEMA: just-message" in txt
    assert "SCHEMA [policy_index=2]" in txt
