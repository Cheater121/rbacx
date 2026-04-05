"""Unit tests for require_batch_access FastAPI dependency."""

from unittest.mock import MagicMock

import pytest

from rbacx import Guard, Subject

_POLICY_MIXED = {
    "algorithm": "deny-overrides",
    "rules": [
        {"id": "r-read", "effect": "permit", "actions": ["read"], "resource": {"type": "doc"}},
        {
            "id": "r-write",
            "effect": "permit",
            "actions": ["write"],
            "resource": {"type": "doc"},
            "roles": ["editor", "admin"],
        },
    ],
}

_S_VIEWER = Subject(id="u1", roles=["viewer"])
_S_EDITOR = Subject(id="u2", roles=["editor"])


def _fake_request(subject: Subject) -> MagicMock:
    req = MagicMock()
    req._subject = subject
    return req


# ---------------------------------------------------------------------------
# Stubs — avoid FastAPI install
# ---------------------------------------------------------------------------


def _patch_fastapi(monkeypatch):
    import rbacx.adapters.fastapi as mod

    fake_http_exc = type(
        "HTTPException",
        (Exception,),
        {"__init__": lambda self, status_code=403, detail="", headers=None: None},
    )
    monkeypatch.setattr(mod, "HTTPException", fake_http_exc, raising=False)
    monkeypatch.setattr(mod, "Request", MagicMock, raising=False)


# ---------------------------------------------------------------------------
# Basic permit / deny
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_require_batch_access_returns_decisions(monkeypatch):
    """require_batch_access resolves to a list of Decision objects."""
    _patch_fastapi(monkeypatch)
    from rbacx.adapters.fastapi import require_batch_access

    guard = Guard(_POLICY_MIXED)

    def build_subject(request):
        return request._subject

    dep = require_batch_access(
        guard,
        [("read", "doc"), ("write", "doc")],
        build_subject,
    )

    req = _fake_request(_S_VIEWER)
    decisions = await dep(req)
    assert len(decisions) == 2
    assert decisions[0].allowed is True  # viewer can read
    assert decisions[1].allowed is False  # viewer cannot write


@pytest.mark.asyncio
async def test_require_batch_access_editor_can_write(monkeypatch):
    """Editor role passes the write check."""
    _patch_fastapi(monkeypatch)
    from rbacx.adapters.fastapi import require_batch_access

    guard = Guard(_POLICY_MIXED)

    def build_subject(request):
        return request._subject

    dep = require_batch_access(
        guard,
        [("read", "doc"), ("write", "doc")],
        build_subject,
    )

    req = _fake_request(_S_EDITOR)
    decisions = await dep(req)
    assert decisions[0].allowed is True
    assert decisions[1].allowed is True


# ---------------------------------------------------------------------------
# Empty actions_resources
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_require_batch_access_empty_actions(monkeypatch):
    """Empty actions_resources returns empty list."""
    _patch_fastapi(monkeypatch)
    from rbacx.adapters.fastapi import require_batch_access

    guard = Guard(_POLICY_MIXED)
    dep = require_batch_access(guard, [], lambda req: _S_VIEWER)
    decisions = await dep(_fake_request(_S_VIEWER))
    assert decisions == []


# ---------------------------------------------------------------------------
# Order preserved
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_require_batch_access_order_preserved(monkeypatch):
    """Results are in the same order as actions_resources."""
    _patch_fastapi(monkeypatch)
    from rbacx.adapters.fastapi import require_batch_access

    policy = {
        "algorithm": "deny-overrides",
        "rules": [
            {"id": "r1", "effect": "permit", "actions": ["read"], "resource": {"type": "a"}},
            {"id": "r2", "effect": "deny", "actions": ["write"], "resource": {"type": "b"}},
            {"id": "r3", "effect": "permit", "actions": ["exec"], "resource": {"type": "c"}},
        ],
    }
    guard = Guard(policy)
    dep = require_batch_access(
        guard,
        [("read", "a"), ("write", "b"), ("exec", "c")],
        lambda req: Subject(id="u"),
    )
    decisions = await dep(_fake_request(Subject(id="u")))
    assert [d.allowed for d in decisions] == [True, False, True]


# ---------------------------------------------------------------------------
# Timeout propagated
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_require_batch_access_timeout_propagated(monkeypatch):
    """timeout parameter is passed through to evaluate_batch_async."""
    _patch_fastapi(monkeypatch)
    from rbacx.adapters.fastapi import require_batch_access

    guard = Guard(_POLICY_MIXED)
    observed_timeout: list[float | None] = []

    original = guard.evaluate_batch_async

    async def patched(requests, *, timeout=None, **kw):
        observed_timeout.append(timeout)
        return await original(requests, timeout=timeout, **kw)

    guard.evaluate_batch_async = patched  # type: ignore[method-assign]

    dep = require_batch_access(
        guard,
        [("read", "doc")],
        lambda req: _S_VIEWER,
        timeout=2.5,
    )
    await dep(_fake_request(_S_VIEWER))
    assert observed_timeout == [2.5]


# ---------------------------------------------------------------------------
# Coverage: prometheus/otel batch_hist.observe/record paths
# ---------------------------------------------------------------------------


def test_prometheus_batch_size_observe_routing():
    """PrometheusMetrics routes 'rbacx_batch_size' to _batch_hist."""
    import importlib
    import sys
    import types

    # Install a fake prometheus_client with a Histogram that accepts **kw
    fake = types.ModuleType("prometheus_client")
    observed_batch: list[float] = []
    observed_latency: list[float] = []

    class FakeHist:
        def __init__(self, name, doc, **kw):
            self._name = name

        def observe(self, v):
            if "batch" in self._name:
                observed_batch.append(v)
            else:
                observed_latency.append(v)

    class FakeCnt:
        def __init__(self, *a, **kw):
            pass

        def labels(self, **kw):
            class C:
                def inc(self):
                    pass

            return C()

    fake.Counter = FakeCnt
    fake.Histogram = FakeHist
    sys.modules["prometheus_client"] = fake

    try:
        import rbacx.metrics.prometheus as pm_mod

        importlib.reload(pm_mod)
        m = pm_mod.PrometheusMetrics()
        m.observe("rbacx_batch_size", 7.0)
        m.observe("rbacx_decision_seconds", 0.01)
        assert observed_batch == [7.0]
        assert observed_latency == [0.01]
    finally:
        sys.modules.pop("prometheus_client", None)
        importlib.reload(pm_mod)


def test_otel_batch_size_observe_routing():
    """OpenTelemetryMetrics routes 'rbacx_batch_size' to _batch_hist."""
    import importlib
    import sys
    import types

    recorded: dict[str, list] = {"batch": [], "latency": []}

    class FakeHist:
        def __init__(self, name):
            self._name = name

        def record(self, v, attributes=None):
            if "batch" in self._name:
                recorded["batch"].append(v)
            else:
                recorded["latency"].append(v)

    class FakeMeter:
        def create_counter(self, *a, **kw):
            class C:
                def add(self, v, attrs=None):
                    pass

            return C()

        def create_histogram(self, name, **kw):
            return FakeHist(name)

    fake_otel = types.ModuleType("opentelemetry.metrics")
    fake_otel.get_meter = lambda name: FakeMeter()
    sys.modules["opentelemetry"] = types.ModuleType("opentelemetry")
    sys.modules["opentelemetry.metrics"] = fake_otel

    try:
        import rbacx.metrics.otel as otel_mod

        importlib.reload(otel_mod)
        m = otel_mod.OpenTelemetryMetrics()
        m.observe("rbacx_batch_size", 5.0)
        m.observe("rbacx_decision_seconds", 0.002)
        assert recorded["batch"] == [5.0]
        assert recorded["latency"] == [0.002]
    finally:
        sys.modules.pop("opentelemetry", None)
        sys.modules.pop("opentelemetry.metrics", None)
        importlib.reload(otel_mod)


# ---------------------------------------------------------------------------
# Coverage: batch_hist is None (prometheus/otel not installed)
# ---------------------------------------------------------------------------


def test_prometheus_batch_size_observe_batch_hist_none():
    """observe('rbacx_batch_size') is a no-op when _batch_hist is None (99→exit)."""
    import importlib
    import sys
    import types

    fake = types.ModuleType("prometheus_client")

    class FakeCnt:
        def __init__(self, *a, **kw):
            pass

        def labels(self, **kw):
            class C:
                def inc(self):
                    pass

            return C()

    class FakeHist:
        def __init__(self, name, doc, **kw):
            self._name = name

        def observe(self, v):
            pass

    fake.Counter = FakeCnt
    fake.Histogram = FakeHist
    sys.modules["prometheus_client"] = fake

    try:
        import rbacx.metrics.prometheus as pm_mod

        importlib.reload(pm_mod)
        m = pm_mod.PrometheusMetrics()
        # Force _batch_hist to None to simulate creation failure
        m._batch_hist = None
        # Must not raise — silently no-ops (transition 99→exit)
        m.observe("rbacx_batch_size", 3.0)
    finally:
        sys.modules.pop("prometheus_client", None)
        importlib.reload(pm_mod)


def test_otel_batch_size_observe_batch_hist_none():
    """observe('rbacx_batch_size') is a no-op when _batch_hist is None (117→exit)."""
    import importlib
    import sys
    import types

    class FakeMeter:
        def create_counter(self, *a, **kw):
            class C:
                def add(self, v, attrs=None):
                    pass

            return C()

        def create_histogram(self, name, **kw):
            return None

    fake_otel = types.ModuleType("opentelemetry.metrics")
    fake_otel.get_meter = lambda name: FakeMeter()
    sys.modules["opentelemetry"] = types.ModuleType("opentelemetry")
    sys.modules["opentelemetry.metrics"] = fake_otel

    try:
        import rbacx.metrics.otel as otel_mod

        importlib.reload(otel_mod)
        m = otel_mod.OpenTelemetryMetrics()
        # Force _batch_hist to None
        m._batch_hist = None
        # Must not raise — silently no-ops (transition 117→exit)
        m.observe("rbacx_batch_size", 5.0)
    finally:
        sys.modules.pop("opentelemetry", None)
        sys.modules.pop("opentelemetry.metrics", None)
        importlib.reload(otel_mod)
