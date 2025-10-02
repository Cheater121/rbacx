from rbacx import cli


def test_print_text_with_string_already_ending_newline(capsys):
    cli._print("hello\n", "text")
    out = capsys.readouterr().out
    # No extra newline should be added
    assert out == "hello\n"
