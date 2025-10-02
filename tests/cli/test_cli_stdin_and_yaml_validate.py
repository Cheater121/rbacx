
import io
import json
import sys
import types
import pytest
from rbacx import cli

def test_cmd_validate_reads_from_stdin_text(monkeypatch, capsys):
    stdin = io.StringIO(json.dumps({"rules": []}))
    monkeypatch.setattr(sys, "stdin", stdin, raising=True)

    ns = types.SimpleNamespace(policy=None, policyset=False, format="text")
    code = cli.cmd_validate(ns)
    out = capsys.readouterr().out.strip()

    assert code == cli.EXIT_OK
    assert out == "OK"

def test_cli_validate_accepts_yaml(tmp_path, monkeypatch, capsys):
    yaml = pytest.importorskip("yaml")

    p = tmp_path / "p.yaml"
    p.write_text("rules: []\n", encoding="utf-8")

    rc = cli.main(["validate", "--policy", str(p), "--format", "json"])
    out = capsys.readouterr().out.strip()

    assert rc == cli.EXIT_OK
    assert out == "[]"
