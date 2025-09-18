import sys
import types

from rbacx.store.http_store import HTTPPolicySource


def test_http_uses_lowercase_content_type_and_bytes_fallback(monkeypatch):
    # First successful YAML load to populate cache and etag
    class Resp1:
        status_code = 200
        headers = {"etag": '"abc"', "content-type": "application/x-yaml"}
        text = "rules: []\nalgorithm: permit-overrides"

        def raise_for_status(self):
            return None

    # Next request returns 304 Not Modified
    class Resp304:
        status_code = 304
        headers = {}

        def raise_for_status(self):
            return None

    calls = []

    def fake_get(url, headers, timeout):
        calls.append(headers.copy())
        return Resp1() if len(calls) == 1 else Resp304()

    req_mod = types.SimpleNamespace(get=fake_get)
    monkeypatch.setitem(sys.modules, "requests", req_mod)

    src = HTTPPolicySource("http://example/policy.yml")
    pol1 = src.load()
    assert src.etag() == '"abc"'
    # Conditional GET should include If-None-Match
    pol2 = src.load()
    assert pol2 == pol1
    assert any("If-None-Match" in h for h in calls[1:])


def test_http_bytes_decode_error_with_yaml_content_type(monkeypatch):
    class Resp:
        status_code = 200
        headers = {"Content-Type": "application/yaml", "ETag": 'W/"v1"'}
        text = None
        # invalid utf-8 bytes:
        content = b"\xff\xfe\xff"

        def raise_for_status(self):
            return None

    def fake_get(url, headers, timeout):
        return Resp()

    req_mod = types.SimpleNamespace(get=fake_get)
    monkeypatch.setitem(sys.modules, "requests", req_mod)

    src = HTTPPolicySource("http://example/policy.yaml")
    pol = src.load()
    # YAML empty due to decode failure -> empty dict
    assert isinstance(pol, dict)
