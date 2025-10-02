import pytest

from rbacx import cli


def test_main_version_returns_ok_no_systemexit(capsys):
    rc = cli.main(["--version"])
    out = capsys.readouterr().out
    assert rc == cli.EXIT_OK
    assert "rbacx" in out


def test_main_unknown_flag_raises_systemexit():
    with pytest.raises(SystemExit) as e:
        cli.main(["--no-such-flag"])
    assert e.value.code != 0
