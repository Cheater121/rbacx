import sys
import types
import importlib
import importlib.util

import pytest

import rbacx.store.http_store as http


class _Resp:
    def __init__(self, status=200, headers=None, json_obj=None, text=None, content=None, json_exc=None):
        self.status_code = status
        self.headers = headers or {}
        self._json = json_obj
        self.text = text
        self.content = content
        self._json_exc = json_exc

    def json(self):
        if self._json_exc:
            raise self._json_exc
        return self._json

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError("HTTP error")


def _install_requests(monkeypatch, resp: _Resp):
    monkeypatch.setitem(sys.modules, "requests", types.SimpleNamespace(get=lambda *a, **k: resp))


# Lines 110–112: except around r.json() should fall through to text parsing
def test_http_json_fallback_when_json_raises_goes_to_text(monkeypatch):
    # Content-Type: json; empty body; r.json() raises -> must call parse_policy_text
    resp = _Resp(
        200,
        {"ETag": "E-fb1", "Content-Type": "application/json"},
        json_exc=ValueError("boom"),
        text="",  # no body text
        content=None,
    )
    _install_requests(monkeypatch, resp)

    seen = {"called": False}

    def fake_parse(text, *, filename=None, content_type=None, **kw):
        seen["called"] = True
        return {"ok": True}

    monkeypatch.setattr(http, "parse_policy_text", fake_parse, raising=True)

    src = http.HTTPPolicySource("http://x/policy.json", validate_schema=False)
    out = src.load()

    assert out == {"ok": True}
    assert seen["called"] is True  # proves fallback executed (110–112)


# Transition 113 -> 121: r.json() returns non-dict -> fall through to parse_policy_text
def test_http_json_fallback_when_non_dict_goes_to_text(monkeypatch):
    resp = _Resp(
        200,
        {"ETag": "E-fb2", "Content-Type": "application/json"},
        json_obj=[1, 2, 3],  # non-dict
        text="",  # empty body to force fallback decision
        content=None,
    )
    _install_requests(monkeypatch, resp)

    seen = {"text_called": False, "validated": 0}

    def fake_parse(text, *, filename=None, content_type=None, **kw):
        seen["text_called"] = True
        return {"parsed": True}

    monkeypatch.setattr(http, "parse_policy_text", fake_parse, raising=True)

    # Even with validation on, we only validate after parse in the text branch
    fake_validate = types.SimpleNamespace(validate_policy=lambda p: seen.__setitem__("validated", seen["validated"] + 1))
    monkeypatch.setitem(sys.modules, "rbacx.dsl.validate", fake_validate)

    src = http.HTTPPolicySource("http://x/p.json", validate_schema=True)
    out = src.load()

    assert out == {"parsed": True}
    assert seen["text_called"] is True  # 113 -> 121 fallthrough confirmed
    assert seen["validated"] == 1       # validated in text branch (124–125)


# Lines 118–119: caching + return for JSON early-return branch
def test_http_json_early_return_caches_and_reuses_on_304(monkeypatch):
    objs = [
        _Resp(200, {"ETag": "E-json", "Content-Type": "application/json"}, json_obj={"a": 1}),
        _Resp(304, {}),  # Not Modified -> should reuse cached policy
    ]
    calls = {"i": 0}

    def _get(*a, **k):
        i = calls["i"]
        calls["i"] += 1
        return objs[i]

    monkeypatch.setitem(sys.modules, "requests", types.SimpleNamespace(get=_get))

    src = http.HTTPPolicySource("http://example/p.json", validate_schema=False)
    first = src.load()
    second = src.load()

    assert first == {"a": 1}
    assert second == {"a": 1}  # proves lines 118–119 cached and returned


# Lines 124–125: validation is called after parse_policy_text in text branch
def test_http_text_branch_validates_after_parse(monkeypatch):
    # Force text branch: provide YAML content-type and text body
    resp = _Resp(
        200,
        {"ETag": "E-text", "Content-Type": "application/yaml"},
        json_obj=None,
        text="rules: []\n",
        content=None,
    )
    _install_requests(monkeypatch, resp)

    # Use the real parse_policy_text path by default; just stub validate
    called = {"n": 0, "arg": None}
    def _vp(p):
        called["n"] += 1
        called["arg"] = p

    monkeypatch.setitem(sys.modules, "rbacx.dsl.validate", types.SimpleNamespace(validate_policy=_vp))

    src = http.HTTPPolicySource("http://example/p.yaml", validate_schema=True)
    out = src.load()

    assert isinstance(out, dict)
    assert called["n"] == 1, "validate_policy should be called exactly once in text branch"
    assert called["arg"] == out  # validate called with parsed policy (124–125)
