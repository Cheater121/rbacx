
from rbacx import cli

def test_main_version_flag_smoke(capsys):
    rc = cli.main(["--version"])
    out = capsys.readouterr().out.strip()
    assert rc == cli.EXIT_OK
    assert "rbacx" in out

def test_main_usage_no_subcommand(capsys):
    rc = cli.main([])
    out = capsys.readouterr().out.lower()
    assert rc == cli.EXIT_USAGE
    assert "usage:" in out
