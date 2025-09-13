import sys
import types

import pytest


def make_requests_stub(status_code=200, etag=None, json_obj=None, capture=None):
    class Resp:
        def __init__(self):
            self.status_code = status_code
            self.headers = {}
            if etag is not None:
                self.headers["ETag"] = etag

        def raise_for_status(self):
            return None

        def json(self):
            return json_obj if json_obj is not None else {}

    m = types.SimpleNamespace()

    def _get(url, headers=None, timeout=None):
        if capture is not None:
            capture.append(dict(url=url, headers=headers or {}, timeout=timeout))
        return Resp()

    m.get = _get
    return m


def test_http_source_success_and_etag_update(monkeypatch):
    calls = []
    requests_mod = make_requests_stub(
        status_code=200, etag='W/"123"', json_obj={"ok": True}, capture=calls
    )
    monkeypatch.setitem(sys.modules, "requests", requests_mod)

    from rbacx.store.http_store import HTTPPolicySource

    src = HTTPPolicySource("https://api/policy", headers={"X-Test": "1"})
    data = src.load()
    assert data == {"ok": True}
    assert src.etag() == 'W/"123"'
    assert calls and "If-None-Match" not in calls[-1]["headers"]

    # Second call: sends If-None-Match and updates the ETag
    calls.clear()
    requests_mod2 = make_requests_stub(
        status_code=200, etag='W/"456"', json_obj={"ok": True}, capture=calls
    )
    monkeypatch.setitem(sys.modules, "requests", requests_mod2)
    data2 = src.load()
    assert data2 == {"ok": True}
    assert src.etag() == 'W/"456"'
    assert calls and calls[-1]["headers"].get("If-None-Match") == 'W/"123"'


def test_http_source_not_modified_returns_empty(monkeypatch):
    calls = []
    monkeypatch.setitem(
        sys.modules,
        "requests",
        make_requests_stub(status_code=304, etag='W/"123"', json_obj={}, capture=calls),
    )

    from rbacx.store.http_store import HTTPPolicySource

    src = HTTPPolicySource("https://api/policy")
    src._etag = 'W/"123"'  # simulate a previous ETag
    data = src.load()
    assert data == {}, "304 with a previous ETag should return an empty dict (no changes)"
    assert calls and calls[-1]["headers"].get("If-None-Match") == 'W/"123"'


def test_http_source_requests_missing_raises_runtimeerror(monkeypatch):
    """
    It's important to guarantee that importing 'requests' raises ImportError,
    otherwise the code would make a real network request.
    """
    # 1) Remove from the import cache to force an actual import
    sys.modules.pop("requests", None)

    # 2) Patch the import mechanism and fail when importing 'requests'
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *a, **kw):
        if name == "requests":
            raise ImportError("No module named 'requests'")
        return real_import(name, *a, **kw)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    from rbacx.store.http_store import HTTPPolicySource

    src = HTTPPolicySource("https://api/policy")
    with pytest.raises(RuntimeError, match="requests is required"):
        src.load()
