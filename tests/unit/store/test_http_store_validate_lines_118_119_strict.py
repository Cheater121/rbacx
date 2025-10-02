import sys
import types
import rbacx.store.http_store as http


class _RespStateful:
    def __init__(self, headers=None, text="", content=None):
        self.status_code = 200
        self.headers = headers or {}
        self.text = text
        self.content = content
        self._calls = 0

    def json(self):
        # First call (fast-path) -> raise to force fall-through;
        # Second call (fallback) -> return dict to hit lines 118–119.
        self._calls += 1
        if self._calls == 1:
            raise ValueError("simulate fast-path json() failure")
        return {"hit": "fallback"}

    def raise_for_status(self):
        pass


def test_http_fallback_cache_and_return_lines_118_119(monkeypatch):
    # Content-Type JSON + empty body -> fallback condition true
    resp = _RespStateful(headers={"ETag": "E-L118", "Content-Type": "application/json"}, text="", content=None)

    # requests.get always returns our stateful response
    monkeypatch.setitem(sys.modules, "requests", types.SimpleNamespace(get=lambda *a, **k: resp))

    # Enable validation to ensure it's called in fallback path (but don't make it fail)
    called = {"n": 0, "arg": None}
    def _vp(obj):
        called["n"] += 1
        called["arg"] = obj
    monkeypatch.setitem(sys.modules, "rbacx.dsl.validate", types.SimpleNamespace(validate_policy=_vp))

    src = http.HTTPPolicySource("http://example/p.json", validate_schema=True)
    out = src.load()

    # We must have executed the fallback success branch:
    # - json() called twice (fast-path fail + fallback success),
    # - object returned equals the fallback dict,
    # - cache was set prior to return (covered by line execution),
    # - validation called once with that object.
    assert out == {"hit": "fallback"}
    assert called["n"] == 1
    assert called["arg"] == out
