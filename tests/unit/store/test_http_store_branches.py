import sys
import types

from rbacx.store.http_store import HTTPPolicySource


# -------- 35–39: 304 Not Modified returns the cached policy --------
def test_http_load_returns_cached_on_304(monkeypatch):
    # Build a minimal fake 'requests' module and a response with 304
    class Resp304:
        status_code = 304
        headers = {}

        def raise_for_status(self):
            pass

    def fake_get(url, headers=None, timeout=None):
        # Ensure If-None-Match can be present but is irrelevant here
        assert isinstance(headers, dict)
        return Resp304()

    fake_requests = types.SimpleNamespace(get=fake_get)
    monkeypatch.setitem(sys.modules, "requests", fake_requests)

    src = HTTPPolicySource("http://example/policy.json")
    # Pre-fill cache so the 304 branch returns it
    src._policy_cache = {"cached": True}

    out = src.load()
    assert out == {"cached": True}


# -------- 55–56: ETag header access raises -> caught and ignored --------
def test_http_load_etag_headers_exception_is_caught(monkeypatch):
    # Response where 'headers.get' raises inside the ETag try/except
    class BadHeaders:
        def get(self, key):  # will be called with "ETag"
            raise RuntimeError("boom-headers")

    class Resp:
        status_code = 200
        headers = BadHeaders()

        def raise_for_status(self):
            pass

        def json(self):
            return []  # non-dict => fall through (covers 65->76 false path)

    def fake_get(url, headers=None, timeout=None):
        return Resp()

    fake_requests = types.SimpleNamespace(get=fake_get)
    monkeypatch.setitem(sys.modules, "requests", fake_requests)

    # Patch parse_policy_text to avoid real parsing and return something deterministic
    import rbacx.store.http_store as httpmod

    monkeypatch.setattr(
        httpmod, "parse_policy_text", lambda text, **kw: {"ok": "parsed"}, raising=True
    )

    src = HTTPPolicySource("http://example/policy.yaml")
    out = src.load()
    assert out == {"ok": "parsed"}  # load proceeds despite header exception


# -------- 65->76 (non-dict JSON path), 81–87 (including 83–84), and 96 (body_text fallback to empty string) --------
def test_http_load_json_non_dict_then_content_type_raises_and_empty_body(monkeypatch):
    # Response where .json() returns non-dict (so continue),
    # Content-Type access raises (to hit the except -> content_type=None),
    # and no .text plus non-bytes .content (to hit body_text = "").
    class BadHeaders:
        def get(self, key):
            # This is for the *Content-Type* block; raise to hit 81–87 except
            if key in ("Content-Type", "content-type"):
                raise RuntimeError("boom-ctype")
            return None

    class Resp:
        status_code = 200
        headers = BadHeaders()
        text = None  # force the .content path
        content = object()  # non-bytes => body_text = "" (line 96)

        def raise_for_status(self):
            pass

        def json(self):
            return []  # non-dict => cover 65->76 "False" path

    def fake_get(url, headers=None, timeout=None):
        return Resp()

    fake_requests = types.SimpleNamespace(get=fake_get)
    monkeypatch.setitem(sys.modules, "requests", fake_requests)

    # Stub parser to verify it receives empty text and returns a marker dict
    seen = {}

    def fake_parse(text, **kw):
        # text must be "" due to non-bytes .content
        seen["text"] = text
        return {"ok": True}

    import rbacx.store.http_store as httpmod

    monkeypatch.setattr(httpmod, "parse_policy_text", fake_parse, raising=True)

    src = HTTPPolicySource("http://example/whatever")
    out = src.load()

    assert out == {"ok": True}
    assert seen["text"] == ""


# -------- JSON fast-path success (dict) --------
def test_http_load_json_fast_path_success_updates_cache_and_returns(monkeypatch):
    class Resp:
        status_code = 200
        headers = {"ETag": "W/123"}  # normal header access (no exception)

        def raise_for_status(self):
            pass

        def json(self):
            return {"k": "v"}  # dict => early return from JSON fast-path

    def fake_get(url, headers=None, timeout=None):
        return Resp()

    fake_requests = types.SimpleNamespace(get=fake_get)
    monkeypatch.setitem(sys.modules, "requests", fake_requests)

    src = HTTPPolicySource("http://example/policy.json")
    out = src.load()
    # Returned as-is and cached internally
    assert out == {"k": "v"}
    assert src._policy_cache == {"k": "v"}
    # ETag also updated
    assert src._etag == "W/123"


# ---------- 81–87: no exception; ctype is None (False branch of isinstance) ----------
def test_http_load_content_type_none_without_exception(monkeypatch):
    class Resp:
        status_code = 200
        headers = {}  # dict present, but no Content-Type / content-type keys
        text = "k: v"  # force text parsing; no .json -> skip JSON fast-path

        def raise_for_status(self):
            pass

        # NOTE: no .json attribute on purpose

    def fake_get(url, headers=None, timeout=None):
        return Resp()

    fake_requests = types.SimpleNamespace(get=fake_get)
    monkeypatch.setitem(sys.modules, "requests", fake_requests)

    # Capture what content_type reaches the parser (should stay None)
    import rbacx.store.http_store as httpmod

    seen = {}

    def fake_parse(text, *, filename=None, content_type=None, **kw):
        seen["content_type"] = content_type
        return {"ok": True}

    monkeypatch.setattr(httpmod, "parse_policy_text", fake_parse, raising=True)

    src = HTTPPolicySource("http://example/policy.yaml")
    out = src.load()

    assert out == {"ok": True}
    assert seen["content_type"] is None
