
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
        if isinstance(self._json, Exception):
            raise self._json
        return self._json

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError("HTTP error")


def _install_requests(monkeypatch, resp: _Resp):
    monkeypatch.setitem(sys.modules, "requests", types.SimpleNamespace(get=lambda *a, **k: resp))


def test_http_no_validation_by_default(monkeypatch):
    # Prepare response with JSON body
    resp = _Resp(200, {"ETag": "E1", "Content-Type": "application/json"}, json_obj={"rules": []})
    _install_requests(monkeypatch, resp)

    # Install validate module stub to capture calls if any
    called = {"n": 0}
    fake_validate = types.SimpleNamespace(validate_policy=lambda p: called.__setitem__("n", called["n"] + 1))
    monkeypatch.setitem(sys.modules, "rbacx.dsl.validate", fake_validate)

    src = http.HTTPPolicySource("http://example/policy.json")
    out = src.load()

    assert isinstance(out, dict)
    assert called["n"] == 0, "validate_policy should NOT be called by default"


def test_http_validation_enabled_calls_validate(monkeypatch):
    resp = _Resp(200, {"ETag": "E2", "Content-Type": "application/json"}, json_obj={"rules": []})
    _install_requests(monkeypatch, resp)

    called = {"args": None}
    def _vp(policy):
        called["args"] = policy

    fake_validate = types.SimpleNamespace(validate_policy=_vp)
    monkeypatch.setitem(sys.modules, "rbacx.dsl.validate", fake_validate)

    src = http.HTTPPolicySource("http://example/p.json", validate_schema=True)
    out = src.load()

    assert called["args"] == out, "validate_policy should be called with parsed policy"
    assert src.etag() == "E2"


def test_http_validation_error_propagates(monkeypatch):
    resp = _Resp(200, {"ETag": "E3", "Content-Type": "application/json"}, json_obj={"rules": []})
    _install_requests(monkeypatch, resp)

    def _vp(_policy):
        raise RuntimeError("bad schema")

    fake_validate = types.SimpleNamespace(validate_policy=_vp)
    monkeypatch.setitem(sys.modules, "rbacx.dsl.validate", fake_validate)

    src = http.HTTPPolicySource("http://example/p.json", validate_schema=True)
    with pytest.raises(RuntimeError):
        src.load()
