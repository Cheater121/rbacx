import sys
import types
import rbacx.store.http_store as http


class _RespStatefulNoValidate:
    def __init__(self, headers=None, text="", content=None):
        self.status_code = 200
        self.headers = headers or {}
        self.text = text
        self.content = content
        self._calls = 0

    def json(self):
        # 1st call (fast-path) -> raise to force fall-through to fallback
        # 2nd call (fallback) -> return dict to hit lines 118–119
        self._calls += 1
        if self._calls == 1:
            raise ValueError("fast-path json() failure")
        return {"fallback": True}

    def raise_for_status(self):
        pass


def test_http_fallback_skips_validation_branch_115_to_118(monkeypatch):
    # JSON content-type + empty body to enable fallback condition
    resp = _RespStatefulNoValidate(headers={"ETag": "E-L115", "Content-Type": "application/json"}, text="", content=None)

    # requests.get returns our stateful response
    monkeypatch.setitem(sys.modules, "requests", types.SimpleNamespace(get=lambda *a, **k: resp))

    # Ensure validation module is NOT injected; we want to prove the branch skips lines 116–117
    if "rbacx.dsl.validate" in sys.modules:
        del sys.modules["rbacx.dsl.validate"]

    src = http.HTTPPolicySource("http://example/p.json", validate_schema=False)
    out = src.load()

    # We should return dict from fallback and NOT have imported validation module at all
    assert out == {"fallback": True}
    assert "rbacx.dsl.validate" not in sys.modules, "validation should not be imported when validate_schema=False"
