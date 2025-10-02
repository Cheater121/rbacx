
import json
import types
from rbacx import cli

def test_cmd_validate_text_errors_with_policy_index(tmp_path, capsys):
    # policy set: first ok, second invalid (actions empty)
    ps = {
        "policies": [
            {"rules": []},
            {"rules": [{"id":"r","effect":"permit","actions": [], "resource":{"type":"doc"}}]}
        ]
    }
    p = tmp_path / "ps.json"
    p.write_text(json.dumps(ps), encoding="utf-8")

    ns = types.SimpleNamespace(policy=str(p), policyset=True, format="text")
    rc = cli.cmd_validate(ns)
    out = capsys.readouterr().out

    assert rc == cli.EXIT_SCHEMA_ERRORS
    assert "SCHEMA [policy_index=1]" in out
