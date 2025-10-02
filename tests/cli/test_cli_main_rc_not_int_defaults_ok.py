import json

from rbacx import cli


def test_main_rc_not_int_defaults_ok(monkeypatch, tmp_path, capsys):
    # Monkeypatch cmd_lint to return non-int to hit fallback
    monkeypatch.setattr(cli, "cmd_lint", lambda args: "NOT-AN-INT", raising=True)
    # Need a real file path for --policy to avoid stdin read
    p = tmp_path / "ok.json"
    p.write_text(json.dumps({"rules": []}), encoding="utf-8")
    rc = cli.main(["lint", "--policy", str(p)])
    capsys.readouterr().out
    assert rc == cli.EXIT_OK
