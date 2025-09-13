import types

from rbacx.adapters.django.trace import TraceIdMiddleware
from rbacx.logging.context import get_current_trace_id


def test_trace_id_middleware_uses_header_and_clears_context():
    def get_response(req):
        return {}

    mw = TraceIdMiddleware(get_response)
    req = types.SimpleNamespace(META={"HTTP_X_REQUEST_ID": "abc-123"})
    resp = mw(req)
    assert resp["X-Request-ID"] == "abc-123"
    assert get_current_trace_id() is None


def test_trace_id_middleware_generates_when_missing():
    def get_response(req):
        return {}

    mw = TraceIdMiddleware(get_response)
    req = types.SimpleNamespace(META={})
    resp = mw(req)
    assert "X-Request-ID" in resp
    assert isinstance(resp["X-Request-ID"], str) and resp["X-Request-ID"]
    assert get_current_trace_id() is None
