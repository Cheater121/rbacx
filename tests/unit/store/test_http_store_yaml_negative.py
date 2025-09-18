import sys

import pytest

from rbacx.store.http_store import HTTPPolicySource


def test_http_policy_source_yaml_without_pyyaml_raises(monkeypatch):
    pytest.importorskip("requests")

    class DummyResp:
        status_code = 200
        text = "rules: []\n"
        headers = {"Content-Type": "application/x-yaml"}

        def raise_for_status(self): ...

    import requests

    monkeypatch.setattr(requests, "get", lambda url, headers, timeout: DummyResp())
    # Simulate missing PyYAML
    monkeypatch.setitem(sys.modules, "yaml", None)

    src = HTTPPolicySource("http://example.test/policy.yaml")
    with pytest.raises(ImportError):
        src.load()
