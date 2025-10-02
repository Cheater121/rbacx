
import re
from rbacx import cli

def test_build_parser_has_version_flag():
    p = cli.build_parser()
    help_text = p.format_help()
    assert "--version" in help_text

def test_main_without_subcommand_returns_usage_code(capsys):
    rc = cli.main([])
    out = capsys.readouterr().out
    assert rc == cli.EXIT_USAGE
    assert "usage:" in out.lower()
