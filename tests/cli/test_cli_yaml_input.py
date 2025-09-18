import pytest

from rbacx import cli as cli


def test_cli_lint_accepts_yaml(tmp_path, monkeypatch):
    # Skip if PyYAML is not installed (optional dep)
    pytest.importorskip("yaml")

    called = {"policy": False, "policyset": False}

    def fake_analyze_policy(data, require_attrs=None):
        called["policy"] = True
        # Return deterministic result printed as JSON by CLI
        return {"ok": True}

    def fake_analyze_policyset(data, require_attrs=None):
        called["policyset"] = True
        return {"ok": True}

    monkeypatch.setattr(cli, "analyze_policy", fake_analyze_policy, raising=True)
    monkeypatch.setattr(cli, "analyze_policyset", fake_analyze_policyset, raising=True)

    # YAML single-policy (dict) file
    p = tmp_path / "p.yaml"
    p.write_text("rules: []\n", encoding="utf-8")

    # Run CLI with YAML policy
    cli.main(["lint", "--policy", str(p)])

    # Should treat as single policy and not policyset
    assert called == {"policy": True, "policyset": False}
