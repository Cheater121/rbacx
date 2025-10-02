import pytest

from rbacx import cli


def test_validate_doc_re_raises_runtimeerror_single_policy(monkeypatch):
    def boom(doc):
        raise RuntimeError("missing optional dep")

    monkeypatch.setattr(cli, "validate_policy", boom, raising=True)
    with pytest.raises(RuntimeError):
        cli._validate_doc({"rules": []}, policyset=False)


def test_validate_doc_re_raises_runtimeerror_policyset(monkeypatch):
    def boom(doc):
        raise RuntimeError("missing optional dep")

    monkeypatch.setattr(cli, "validate_policy", boom, raising=True)
    with pytest.raises(RuntimeError):
        cli._validate_doc({"policies": [{"rules": []}]}, policyset=True)
