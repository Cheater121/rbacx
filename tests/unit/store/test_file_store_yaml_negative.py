import sys

import pytest

from rbacx.store.file_store import FilePolicySource


def test_file_policy_source_yaml_without_pyyaml_raises(tmp_path, monkeypatch):
    # Simulate missing optional dependency
    monkeypatch.setitem(sys.modules, "yaml", None)
    p = tmp_path / "policy.yaml"
    p.write_text("rules: []\n", encoding="utf-8")
    src = FilePolicySource(str(p), validate_schema=False)
    with pytest.raises(ImportError):
        src.load()
