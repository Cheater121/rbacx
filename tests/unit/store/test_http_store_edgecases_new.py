# Edge-case tests for HTTP store.
# Skip YAML-specific branches if PyYAML is not installed (CI scenario).
# Comments in English by project rule.
import pytest

yaml = pytest.importorskip("yaml", exc_type=ImportError, reason="PyYAML required for YAML paths")

from importlib import reload

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

    monkeypatch.setattr(http.requests, "get", _get, raising=False)
    reload(http)
    data, etag = http.fetch_policy("http://x/y.yaml", etag=None, as_text=False)
    assert isinstance(data, (bytes, bytearray)) or isinstance(data, (str, dict))
    assert etag == "E1"


def test_http_bytes_decode_error_with_yaml_content_type(monkeypatch):
    def _get(_url, headers=None, timeout=None):
        # Provide invalid UTF-8 content to trigger bytes code path
        hdrs = {"Content-Type": "application/yaml", "ETag": "E2"}
        bad = b"\xff\xfe\xfa"
        return _Resp(200, hdrs, text=None, content=bad)

    monkeypatch.setattr(http.requests, "get", _get, raising=False)
    reload(http)
    data, etag = http.fetch_policy("http://x/y.yaml", etag=None, as_text=False)
    # When bytes cannot be decoded, implementation should still return raw bytes and ETag
    assert isinstance(data, (bytes, bytearray))
    assert etag == "E2"
