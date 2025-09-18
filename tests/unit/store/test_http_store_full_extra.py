import sys
import types

import pytest

from rbacx.store.http_store import HTTPPolicySource


def test_http_json_path_sets_etag_case_insensitive(monkeypatch):
    # Build a dummy requests module
    class Resp:
        status_code = 200
        headers = {"etag": 'W/"123"', "Content-Type": "application/json"}

        def json(self):
            return {"ok": True}

        def raise_for_status(self): ...

    def fake_get(url, headers, timeout):
        return Resp()

    req_mod = types.SimpleNamespace(get=fake_get)
    monkeypatch.setitem(sys.modules, "requests", req_mod)

    src = HTTPPolicySource("http://example/policy.json")
    data = src.load()
    assert data == {"ok": True}
    # ETag should be captured even if headers used lowercase
    assert src.etag() == 'W/"123"'


def test_http_yaml_uses_content_bytes_when_no_text(monkeypatch):
    pytest.importorskip("yaml")

    class Resp:
        status_code = 200
        headers = {"Content-Type": "application/x-yaml"}
        content = b"rules: []\n"

        def raise_for_status(self): ...

    def fake_get(url, headers, timeout):
        return Resp()

    req_mod = types.SimpleNamespace(get=fake_get)
    monkeypatch.setitem(sys.modules, "requests", req_mod)

    src = HTTPPolicySource("http://example/policy.yaml")
    data = src.load()
    assert data.get("rules") == []
    # ETag absent -> still fine
    assert src.etag() is None


def test_http_304_not_modified_returns_empty_when_etag_present(monkeypatch):
    class Resp:
        status_code = 304
        headers = {}

        def raise_for_status(self): ...

    calls = []

    def fake_get(url, headers, timeout):
        calls.append(headers.copy())
        return Resp()

    req_mod = types.SimpleNamespace(get=fake_get)
    monkeypatch.setitem(sys.modules, "requests", req_mod)

    src = HTTPPolicySource("http://example/policy.json", headers={"X": "Y"})
    # seed etag to enable 304 path
    src._etag = 'W/"seed"'
    out = src.load()
    assert out == {}
    # Must send If-None-Match
    assert any("If-None-Match" in h for h in calls)


def test_http_json_method_failure_falls_back_to_text(monkeypatch):
    class Resp:
        status_code = 200
        headers = {"Content-Type": "application/json", "ETag": "E"}
        text = '{"rules": []}'

        def json(self):
            raise ValueError("broken json method")

        def raise_for_status(self): ...

    def fake_get(url, headers, timeout):
        return Resp()

    req_mod = types.SimpleNamespace(get=fake_get)
    monkeypatch.setitem(sys.modules, "requests", req_mod)

    src = HTTPPolicySource("http://example/p.json")
    out = src.load()
    assert out.get("rules") == []
    assert src.etag() == "E"


def test_http_missing_requests_raises_runtimeerror(monkeypatch):
    # Simulate requests not installed
    monkeypatch.setitem(sys.modules, "requests", None)
    src = HTTPPolicySource("http://example/p.json")
    with pytest.raises(RuntimeError):
        src.load()


def test_http_raise_for_status_propagates(monkeypatch):
    class HTTPError(Exception): ...

    class Resp:
        status_code = 500
        headers = {}

        def raise_for_status(self):
            raise HTTPError("boom")

    def fake_get(url, headers, timeout):
        return Resp()

    req_mod = types.SimpleNamespace(get=fake_get)
    monkeypatch.setitem(sys.modules, "requests", req_mod)

    src = HTTPPolicySource("http://example/p.json")
    with pytest.raises(HTTPError):
        src.load()
