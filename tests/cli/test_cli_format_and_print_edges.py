from rbacx import cli


def test_format_issues_text_includes_policy_index_and_path():
    issues = [
        {
            "code": "DEMO",
            "message": "m",
            "path": "/rules/0",
            "policy_index": 2,
        }
    ]
    txt = cli._format_issues_text(issues)
    assert "DEMO" in txt
    assert "[policy_index=2]" in txt
    assert "/rules/0" in txt
    assert ": m" in txt


def test_print_text_with_string_without_trailing_newline(capsys):
    cli._print("hello", "text")
    out = capsys.readouterr().out
    assert out.endswith("\n")
    assert out.strip() == "hello"
