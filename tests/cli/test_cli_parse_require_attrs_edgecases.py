import json

from rbacx.cli import _parse_require_attrs, main


def test_parse_require_attrs_none_and_empty():
    assert _parse_require_attrs(None) == {}
    assert _parse_require_attrs("") == {}
    assert _parse_require_attrs(";;") == {}


def test_parse_require_attrs_various_spacing_and_duplicates():
    s = "subject:a,b;resource:x,y,z;action:read,write"
    out = _parse_require_attrs(s)
    assert out == {
        "subject": ["a", "b"],
        "resource": ["x", "y", "z"],
        "action": ["read", "write"],
    }


def test_parse_require_attrs_includes_empty_and_empty_key():
    s = "subject:a,b;ignored;resource:x;bad:;:oops"
    out = _parse_require_attrs(s)
    # 'ignored' is dropped (no colon), 'bad:' keeps empty list, ':oops' yields empty key
    assert out == {"subject": ["a", "b"], "resource": ["x"], "bad": [], "": ["oops"]}


def test_main_without_subcommand_prints_help(capsys):
    main([])
    out = capsys.readouterr().out
    assert "usage:" in out and "lint" in out


def test_main_with_lint_invokes_func(monkeypatch, capsys, tmp_path):
    called = {}
    import rbacx.cli as cli

    def fake_analyze_policy(*args, **kwargs):
        called["policy"] = True
        return {"ok": True}

    def fake_analyze_policyset(*args, **kwargs):
        called["policyset"] = True
        return {"ok": True}

    monkeypatch.setattr(cli, "analyze_policy", fake_analyze_policy, raising=True)
    monkeypatch.setattr(cli, "analyze_policyset", fake_analyze_policyset, raising=True)

    # Create a temp policy file (single policy dict)
    path = tmp_path / "p.json"
    path.write_text(json.dumps({"rules": []}), encoding="utf-8")

    # Run CLI with --policy pointing to file
    main(["lint", "--policy", str(path)])

    # Since it's a single policy (not policyset), only analyze_policy should be called
    assert called == {"policy": True}
