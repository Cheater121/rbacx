"""Unit tests for evaluate_batch_async/sync timeout parameter."""

import asyncio
from unittest.mock import patch

import pytest

from rbacx import Action, Context, Guard, Resource, Subject

_POLICY = {
    "algorithm": "deny-overrides",
    "rules": [
        {"id": "r1", "effect": "permit", "actions": ["read"], "resource": {"type": "doc"}},
    ],
}
_S = Subject(id="u1")
_R = Resource(type="doc", id="1")
_CTX = Context()
_REQ = [(_S, Action("read"), _R, _CTX)]


# ---------------------------------------------------------------------------
# timeout=None — default, no deadline
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_batch_async_no_timeout_succeeds():
    """evaluate_batch_async without timeout completes normally."""
    guard = Guard(_POLICY)
    results = await guard.evaluate_batch_async(_REQ, timeout=None)
    assert len(results) == 1 and results[0].allowed is True


def test_batch_sync_no_timeout_succeeds():
    """evaluate_batch_sync without timeout completes normally."""
    guard = Guard(_POLICY)
    results = guard.evaluate_batch_sync(_REQ, timeout=None)
    assert len(results) == 1 and results[0].allowed is True


# ---------------------------------------------------------------------------
# timeout — normal completion within deadline
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_batch_async_with_generous_timeout_succeeds():
    """evaluate_batch_async with ample timeout completes normally."""
    guard = Guard(_POLICY)
    results = await guard.evaluate_batch_async(_REQ, timeout=10.0)
    assert len(results) == 1 and results[0].allowed is True


def test_batch_sync_with_generous_timeout_succeeds():
    guard = Guard(_POLICY)
    results = guard.evaluate_batch_sync(_REQ, timeout=10.0)
    assert len(results) == 1 and results[0].allowed is True


# ---------------------------------------------------------------------------
# timeout — exceeded raises asyncio.TimeoutError
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_batch_async_timeout_exceeded_raises():
    """evaluate_batch_async raises TimeoutError when batch exceeds deadline."""
    guard = Guard(_POLICY)

    async def slow_evaluate(*args, **kwargs):
        await asyncio.sleep(10)  # simulate slow ReBAC provider

    with patch.object(guard, "_evaluate_core_async", side_effect=slow_evaluate):
        with pytest.raises(asyncio.TimeoutError):
            await guard.evaluate_batch_async(_REQ, timeout=0.01)


# ---------------------------------------------------------------------------
# empty batch — always returns [] regardless of timeout
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_batch_async_empty_returns_empty():
    guard = Guard(_POLICY)
    assert await guard.evaluate_batch_async([], timeout=0.001) == []


def test_batch_sync_empty_returns_empty():
    guard = Guard(_POLICY)
    assert guard.evaluate_batch_sync([], timeout=0.001) == []


# ---------------------------------------------------------------------------
# multiple requests — all complete with timeout
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_batch_async_multiple_requests_with_timeout():
    guard = Guard(_POLICY)
    reqs = [(_S, Action("read"), _R, _CTX) for _ in range(5)]
    results = await guard.evaluate_batch_async(reqs, timeout=5.0)
    assert len(results) == 5
    assert all(d.allowed for d in results)


# ---------------------------------------------------------------------------
# batch_size metric emitted
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_batch_async_emits_batch_size_metric():
    """evaluate_batch_async calls metrics.observe('rbacx_batch_size', N)."""
    observed: list[tuple[str, float]] = []

    class _MockMetrics:
        def inc(self, name, labels=None):
            pass

        def observe(self, name, value, labels=None):
            observed.append((name, value))

    guard = Guard(_POLICY, metrics=_MockMetrics())
    reqs = [(_S, Action("read"), _R, _CTX) for _ in range(3)]
    await guard.evaluate_batch_async(reqs)

    batch_obs = [(n, v) for n, v in observed if n == "rbacx_batch_size"]
    assert len(batch_obs) == 1
    assert batch_obs[0][1] == 3.0


@pytest.mark.asyncio
async def test_batch_async_empty_does_not_emit_metric():
    """evaluate_batch_async with empty input returns early — no metric emitted."""
    observed: list[tuple[str, float]] = []

    class _MockMetrics:
        def inc(self, name, labels=None):
            pass

        def observe(self, name, value, labels=None):
            observed.append((name, value))

    guard = Guard(_POLICY, metrics=_MockMetrics())
    await guard.evaluate_batch_async([])

    batch_obs = [(n, v) for n, v in observed if n == "rbacx_batch_size"]
    assert batch_obs == []


# ---------------------------------------------------------------------------
# Coverage: async metrics.observe + exception in observe
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_batch_async_async_metrics_observe():
    """When metrics.observe is a coroutine, it is awaited correctly."""
    observed: list[tuple[str, float]] = []

    class _AsyncMetrics:
        def inc(self, name, labels=None):
            pass

        async def observe(self, name, value, labels=None):
            observed.append((name, value))

    guard = Guard(_POLICY, metrics=_AsyncMetrics())
    reqs = [(_S, Action("read"), _R, _CTX), (_S, Action("read"), _R, _CTX)]
    await guard.evaluate_batch_async(reqs)

    batch_obs = [(n, v) for n, v in observed if n == "rbacx_batch_size"]
    assert batch_obs == [("rbacx_batch_size", 2.0)]


@pytest.mark.asyncio
async def test_batch_async_metrics_observe_exception_swallowed():
    """Exception in metrics.observe does not propagate — batch result returned."""

    class _RaisingMetrics:
        def inc(self, name, labels=None):
            pass

        def observe(self, name, value, labels=None):
            raise RuntimeError("metrics backend down")

    guard = Guard(_POLICY, metrics=_RaisingMetrics())
    # Must not raise — exception is swallowed and logged
    results = await guard.evaluate_batch_async(_REQ)
    assert len(results) == 1 and results[0].allowed is True
