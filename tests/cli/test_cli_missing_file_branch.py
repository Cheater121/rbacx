
import argparse
import json
import pytest
from rbacx.cli import build_parser, cmd_lint

def test_cmd_lint_missing_file_raises():
    # Non-existent path triggers FileNotFoundError during open()
    ns = argparse.Namespace(policy="/no/such/file.json", require_attrs=None, policyset=False)
    with pytest.raises(FileNotFoundError):
        cmd_lint(ns)

def test_build_parser_help_ok(capsys):
    parser = build_parser()
    try:
        parser.parse_args(["-h"])
    except SystemExit:
        pass
    out = capsys.readouterr().out
    assert "usage:" in out.lower()
