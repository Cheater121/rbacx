import sys
import types

import pytest
import rbacx.store.http_store as http


class _Resp:
    def __init__(self, status=200, headers=None, json_obj=None, text=None, content=None):
        self.status_code = status
        self.headers = headers or {}
        self._json = json_obj
        self.text = text
        self.content = content

    def json(self):
        return self._json

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError("HTTP error")


def test_http_json_fallback_success_validates_caches_and_returns(monkeypatch):
    # First call: Content-Type JSON, empty body -> trigger fallback, r.json() returns dict -> lines 118–119
    first = _Resp(
        200,
        {"ETag": "E-fbOK", "Content-Type": "application/json"},
        json_obj={"ok": True},
        text="",  # empty body to force fallback check
        content=None,
    )
    # Second call: 304 Not Modified -> should reuse cached policy set by line 118
    second = _Resp(304, {}, json_obj=None)

    seq = [first, second]
    idx = {"i": 0}

    def _get(*a, **k):
        i = idx["i"]
        idx["i"] += 1
        return seq[i]

    # Patch requests.get
    monkeypatch.setitem(sys.modules, "requests", types.SimpleNamespace(get=_get))

    # Capture validation calls (should happen once in fallback success path)
    called = {"n": 0, "arg": None}
    def _vp(p):
        called["n"] += 1
        called["arg"] = p

    monkeypatch.setitem(sys.modules, "rbacx.dsl.validate", types.SimpleNamespace(validate_policy=_vp))

    src = http.HTTPPolicySource("http://example/p.json", validate_schema=True)
    out1 = src.load()
    out2 = src.load()

    # Assertions: fallback success returned dict and validated it, and cached result reused on 304
    assert out1 == {"ok": True}
    assert called["n"] == 1
    assert called["arg"] == out1
    assert out2 == {"ok": True}
    # ETag from first response should be stored
    assert src.etag() in ("E-fbOK", 'W/"E-fbOK"')
