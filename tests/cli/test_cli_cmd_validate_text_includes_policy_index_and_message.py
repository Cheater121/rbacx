import json
import types

from rbacx import cli


def test_cmd_validate_text_includes_policy_index_and_message_single_line(
    tmp_path, monkeypatch, capsys
):
    def fake_validate_doc(doc, policyset=False):
        return [{"message": "boom", "policy_index": 7}]

    monkeypatch.setattr(cli, "_validate_doc", fake_validate_doc, raising=True)

    # Provide file path so we don't read stdin
    p = tmp_path / "dummy.json"
    p.write_text(json.dumps({"rules": []}), encoding="utf-8")

    ns = types.SimpleNamespace(policy=str(p), policyset=True, format="text")
    rc = cli.cmd_validate(ns)
    out = capsys.readouterr().out.strip()

    assert rc == cli.EXIT_SCHEMA_ERRORS
    # This line exercises both conditionals in the loop (index+message) and the append
    assert out == "SCHEMA [policy_index=7]: boom"
