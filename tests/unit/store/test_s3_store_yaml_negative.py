import sys

import pytest

from rbacx.store.s3_store import S3PolicySource


def test_s3_policy_source_yaml_without_pyyaml_raises(monkeypatch):
    pytest.importorskip("boto3")
    # Simulate missing PyYAML
    monkeypatch.setitem(sys.modules, "yaml", None)
    src = S3PolicySource("s3://bucket/policy.yml", validate_schema=False)
    # Avoid real AWS; return YAML bytes
    monkeypatch.setattr(src, "_get_object_bytes", lambda: b"rules: []\n")
    with pytest.raises(ImportError):
        src.load()
