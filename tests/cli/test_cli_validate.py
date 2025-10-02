import io
import json
import sys
import types
import pytest

from rbacx import cli


def _ok_policy():
    # Valid per schema (empty rules are allowed)
    return {"rules": []}


def _bad_policy():
    # Invalid per schema: actions must have at least 1 item
    return {
        "rules": [
            {"id": "r", "effect": "permit", "actions": [], "resource": {"type": "doc"}}
        ]
    }


def _policy_set_one_bad():
    return {
        "policies": [
            _ok_policy(),  # index 0: OK
            _bad_policy(), # index 1: invalid
        ]
    }


def test_cmd_validate_json_ok(tmp_path, capsys):
    p = tmp_path / "ok.json"
    p.write_text(json.dumps(_ok_policy()), encoding="utf-8")

    ns = types.SimpleNamespace(policy=str(p), policyset=False, format="json")
    code = cli.cmd_validate(ns)

    out = capsys.readouterr().out.strip()
    assert code == cli.EXIT_OK
    # JSON array with no errors
    assert out == "[]"


def test_cmd_validate_text_ok(tmp_path, capsys):
    p = tmp_path / "ok.json"
    p.write_text(json.dumps(_ok_policy()), encoding="utf-8")

    ns = types.SimpleNamespace(policy=str(p), policyset=False, format="text")
    code = cli.cmd_validate(ns)

    out = capsys.readouterr().out.strip()
    assert code == cli.EXIT_OK
    assert out == "OK"


def test_cmd_validate_json_errors(tmp_path, capsys):
    p = tmp_path / "bad.json"
    p.write_text(json.dumps(_bad_policy()), encoding="utf-8")

    ns = types.SimpleNamespace(policy=str(p), policyset=False, format="json")
    code = cli.cmd_validate(ns)

    out = capsys.readouterr().out.strip()
    assert code == cli.EXIT_SCHEMA_ERRORS
    # Should be a JSON array with at least one error dict
    errs = json.loads(out)
    assert isinstance(errs, list) and errs
    assert all("message" in e for e in errs)


def test_cmd_validate_policyset_indexes_each_policy(tmp_path, capsys):
    p = tmp_path / "ps.json"
    p.write_text(json.dumps(_policy_set_one_bad()), encoding="utf-8")

    ns = types.SimpleNamespace(policy=str(p), policyset=True, format="json")
    code = cli.cmd_validate(ns)

    out = capsys.readouterr().out.strip()
    assert code == cli.EXIT_SCHEMA_ERRORS
    errs = json.loads(out)
    assert isinstance(errs, list) and errs
    # Must point to the second policy (index 1) as invalid
    assert any(e.get("policy_index") == 1 for e in errs)


def test_cmd_validate_reads_from_stdin_json(monkeypatch, capsys):
    # Provide OK policy via stdin when policy path is omitted
    stdin = io.StringIO(json.dumps(_ok_policy()))
    monkeypatch.setattr(sys, "stdin", stdin, raising=True)

    ns = types.SimpleNamespace(policy=None, policyset=False, format="json")
    code = cli.cmd_validate(ns)
    out = capsys.readouterr().out.strip()

    assert code == cli.EXIT_OK
    assert out == "[]"


def test_cmd_validate_missing_optional_dep_maps_to_ENV(monkeypatch, capsys):
    # Simulate missing dependency (jsonschema) by raising RuntimeError from validate_policy
    def boom(*args, **kwargs):
        raise RuntimeError("Install rbacx[validate] to enable schema validation")

    monkeypatch.setattr(cli, "validate_policy", boom, raising=True)

    stdin = io.StringIO(json.dumps(_ok_policy()))
    monkeypatch.setattr(sys, "stdin", stdin, raising=True)

    ns = types.SimpleNamespace(policy=None, policyset=False, format="text")
    code = cli.cmd_validate(ns)
    out = capsys.readouterr().out

    assert code == cli.EXIT_ENV
    assert "Install rbacx[validate]" in out

