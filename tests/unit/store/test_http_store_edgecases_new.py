# Edge-case tests for HTTP store.
# Comments in English by project rule.
import sys
import types
from importlib import reload

import pytest

# Only run these tests when YAML is available, because we target YAML content-type branches.
yaml = pytest.importorskip("yaml", exc_type=ImportError, reason="PyYAML required for YAML paths")

import rbacx.store.http_store as http


class _Resp:
    def __init__(self, status=200, headers=None, text=None, content=None):
        self.status_code = status
        self.headers = headers or {}
        self.text = text
        self.content = content


def test_http_uses_lowercase_content_type_and_bytes_fallback(monkeypatch):
    def _get(_url, headers=None, timeout=None):
        # Lowercase content-type; body is YAML text
        hdrs = {"content-type": "application/yaml", "etag": "E1"}
        txt = "rules:\n  - id: R1\n    effect: permit"
        return _Resp(200, hdrs, text=txt, content=txt.encode("utf-8"))

    # The implementation does `import requests` INSIDE the method,
    # so we must provide a stub in sys.modules for that import.
    monkeypatch.setitem(sys.modules, "requests", types.SimpleNamespace(get=_get))
    reload(http)

    src = http.HTTPPolicySource("http://x/y.yaml")
    policy = src.load()
    assert isinstance(policy, dict) and policy.get("rules")
    assert src.etag() == "E1"


def test_http_bytes_decode_error_with_yaml_content_type(monkeypatch):
    def _get(_url, headers=None, timeout=None):
        # Provide invalid UTF-8 content to trigger bytes fallback path
        hdrs = {"Content-Type": "application/yaml", "ETag": "E2"}
        bad = b"\xff\xfe\xfa"
        return _Resp(200, hdrs, text=None, content=bad)

    monkeypatch.setitem(sys.modules, "requests", types.SimpleNamespace(get=_get))
    reload(http)

    src = http.HTTPPolicySource("http://x/y.yaml")
    policy = src.load()
    assert isinstance(policy, dict)
    assert src.etag() == "E2"
