
from rbacx import cli

def test_print_text_with_non_string_object(capsys):
    cli._print({"k": 1}, "text")
    out = capsys.readouterr().out
    assert out.strip().startswith("{") and out.strip().endswith("}")
