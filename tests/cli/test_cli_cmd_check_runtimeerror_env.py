import io
import sys
import types

from rbacx import cli


def test_cmd_check_runtimeerror_maps_to_exit_env(monkeypatch, capsys):
    def fake_validate_doc(doc, policyset=False):
        raise RuntimeError("Install rbacx[validate] to enable schema validation")

    monkeypatch.setattr(cli, "_validate_doc", fake_validate_doc, raising=True)
    # Provide stdin so cmd_check doesn't try to read the real terminal
    monkeypatch.setattr(sys, "stdin", io.StringIO('{"rules": []}'), raising=True)

    ns = types.SimpleNamespace(policy=None, policyset=False, strict=False, format="text")
    rc = cli.cmd_check(ns)
    out = capsys.readouterr().out
    assert rc == cli.EXIT_ENV
    assert "Install rbacx[validate]" in out
