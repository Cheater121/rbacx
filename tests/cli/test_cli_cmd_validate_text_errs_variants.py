import json
import types

from rbacx import cli


def test_cmd_validate_text_formats_errs_with_and_without_fields(tmp_path, monkeypatch, capsys):
    # Return two errors to exercise both branches inside the loop:
    # - first has only message (no policy_index)
    # - second has only policy_index (no message)
    def fake_validate_doc(doc, policyset=False):
        return [
            {"message": "only-message"},  # triggers 'if msg:' branch
            {"policy_index": 4},  # triggers 'if pidx is not None:' branch
        ]

    monkeypatch.setattr(cli, "_validate_doc", fake_validate_doc, raising=True)

    # Provide an actual file path so cmd_validate reads the file (not stdin)
    p = tmp_path / "dummy_policy.json"
    p.write_text(json.dumps({"rules": []}), encoding="utf-8")

    # Run cmd_validate in text mode
    ns = types.SimpleNamespace(policy=str(p), policyset=True, format="text")
    rc = cli.cmd_validate(ns)
    out_lines = capsys.readouterr().out.strip().splitlines()

    # Should be schema errors and both lines printed (order preserved)
    assert rc == cli.EXIT_SCHEMA_ERRORS
    assert out_lines[0] == "SCHEMA: only-message"
    assert out_lines[1] == "SCHEMA [policy_index=4]"
