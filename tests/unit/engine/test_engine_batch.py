"""Unit tests for Guard.evaluate_batch_async and Guard.evaluate_batch_sync."""

import asyncio
from typing import Any

import pytest

from rbacx.core.engine import Guard
from rbacx.core.model import Action, Context, Resource, Subject

# ---------------------------------------------------------------------------
# Shared fixtures / helpers
# ---------------------------------------------------------------------------

_POLICY_MIXED = {
    "algorithm": "deny-overrides",
    "rules": [
        {"id": "permit-read", "effect": "permit", "actions": ["read"], "resource": {"type": "doc"}},
        {
            "id": "deny-delete",
            "effect": "deny",
            "actions": ["delete"],
            "resource": {"type": "doc"},
        },
    ],
}

_S = Subject(id="u1", roles=["viewer"])
_R = Resource(type="doc", id="d1")
_CTX = Context()


def _guard(**kwargs: Any) -> Guard:
    return Guard(_POLICY_MIXED, **kwargs)


# ---------------------------------------------------------------------------
# evaluate_batch_async — core behaviour
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_batch_async_empty_returns_empty_list():
    """Empty input must return an empty list without any evaluation."""
    g = _guard()
    result = await g.evaluate_batch_async([])
    assert result == []


@pytest.mark.asyncio
async def test_batch_async_single_request_permit():
    """Single-element batch returns a one-element list with the correct Decision."""
    g = _guard()
    results = await g.evaluate_batch_async([(_S, Action("read"), _R, _CTX)])
    assert len(results) == 1
    assert results[0].allowed is True
    assert results[0].effect == "permit"


@pytest.mark.asyncio
async def test_batch_async_single_request_deny():
    """Single deny request is correctly reported."""
    g = _guard()
    results = await g.evaluate_batch_async([(_S, Action("delete"), _R, _CTX)])
    assert len(results) == 1
    assert results[0].allowed is False
    assert results[0].effect == "deny"


@pytest.mark.asyncio
async def test_batch_async_multiple_requests_order_preserved():
    """Results are returned in the same order as the input sequence."""
    g = _guard()
    batch = [
        (_S, Action("read"), _R, _CTX),
        (_S, Action("delete"), _R, _CTX),
        (_S, Action("write"), _R, None),
    ]
    results = await g.evaluate_batch_async(batch)

    assert len(results) == 3
    # read  → permit
    assert results[0].allowed is True and results[0].effect == "permit"
    # delete → deny
    assert results[1].allowed is False and results[1].effect == "deny"
    # write → no rule → deny
    assert results[2].allowed is False and results[2].effect == "deny"


@pytest.mark.asyncio
async def test_batch_async_context_none_is_accepted():
    """Passing None as context must not raise."""
    g = _guard()
    results = await g.evaluate_batch_async([(_S, Action("read"), _R, None)])
    assert results[0].allowed is True


@pytest.mark.asyncio
async def test_batch_async_different_subjects_isolated():
    """Each tuple is evaluated independently; different subjects get independent decisions."""
    policy = {
        "algorithm": "deny-overrides",
        "rules": [
            {
                "id": "owner-only",
                "effect": "permit",
                "actions": ["delete"],
                "resource": {"type": "doc"},
                "condition": {"==": [{"attr": "subject.id"}, "owner"]},
            }
        ],
    }
    g = Guard(policy)
    owner = Subject(id="owner")
    other = Subject(id="stranger")
    resource = Resource(type="doc", id="1")

    results = await g.evaluate_batch_async(
        [
            (owner, Action("delete"), resource, None),
            (other, Action("delete"), resource, None),
        ]
    )

    assert results[0].allowed is True
    assert results[1].allowed is False


@pytest.mark.asyncio
async def test_batch_async_different_resources_isolated():
    """Requests targeting different resources are evaluated independently."""
    policy = {
        "algorithm": "deny-overrides",
        "rules": [
            {
                "id": "only-secret",
                "effect": "deny",
                "actions": ["read"],
                "resource": {"type": "file", "attrs": {"secret": True}},
            },
            {"id": "permit-all", "effect": "permit", "actions": ["read"], "resource": {}},
        ],
    }
    g = Guard(policy)
    s = Subject(id="u")
    public = Resource(type="file", id="pub", attrs={"secret": False})
    secret = Resource(type="file", id="sec", attrs={"secret": True})

    results = await g.evaluate_batch_async(
        [
            (s, Action("read"), public, None),
            (s, Action("read"), secret, None),
        ]
    )

    assert results[0].allowed is True
    assert results[1].allowed is False


@pytest.mark.asyncio
async def test_batch_async_large_batch_all_correct():
    """Stress: 50 concurrent requests all resolve correctly."""
    policy = {
        "algorithm": "deny-overrides",
        "rules": [
            {"id": "r", "effect": "permit", "actions": ["read"], "resource": {"type": "doc"}}
        ],
    }
    g = Guard(policy)
    s = Subject(id="u")
    resource = Resource(type="doc", id="1")
    batch = [(s, Action("read"), resource, None)] * 50

    results = await g.evaluate_batch_async(batch)

    assert len(results) == 50
    assert all(d.allowed for d in results)


# ---------------------------------------------------------------------------
# evaluate_batch_async — DI integration (metrics, logger, obligations)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_batch_async_metrics_called_per_request():
    """Metrics.inc is called once per request in the batch."""

    class CounterMetrics:
        def __init__(self):
            self.calls = 0

        def inc(self, name, labels=None):
            self.calls += 1

    metrics = CounterMetrics()
    g = _guard(metrics=metrics)
    batch = [
        (_S, Action("read"), _R, _CTX),
        (_S, Action("delete"), _R, _CTX),
        (_S, Action("write"), _R, None),
    ]
    await g.evaluate_batch_async(batch)
    assert metrics.calls == 3


@pytest.mark.asyncio
async def test_batch_async_logger_called_per_request():
    """DecisionLogSink.log is called once per request in the batch."""

    class RecordingSink:
        def __init__(self):
            self.payloads = []

        def log(self, payload):
            self.payloads.append(payload)

    sink = RecordingSink()
    g = _guard(logger_sink=sink)
    batch = [(_S, Action("read"), _R, _CTX), (_S, Action("delete"), _R, _CTX)]
    await g.evaluate_batch_async(batch)
    assert len(sink.payloads) == 2


@pytest.mark.asyncio
async def test_batch_async_obligations_checked_per_request():
    """ObligationChecker.check is called once per request."""

    class CountingChecker:
        def __init__(self):
            self.calls = 0

        def check(self, raw, ctx):
            self.calls += 1
            decision = raw.get("decision", "deny")
            return decision == "permit", None

    checker = CountingChecker()
    g = _guard(obligation_checker=checker)
    batch = [(_S, Action("read"), _R, _CTX)] * 4
    await g.evaluate_batch_async(batch)
    assert checker.calls == 4


# ---------------------------------------------------------------------------
# evaluate_batch_async — cache interaction
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_batch_async_cache_hit_on_repeated_identical_request():
    """Identical requests in a batch both return the same cached result after first eval."""
    from rbacx.core.cache import DefaultInMemoryCache

    cache = DefaultInMemoryCache()

    class CountingChecker:
        def __init__(self):
            self.calls = 0

        def check(self, raw, ctx):
            self.calls += 1
            decision = raw.get("decision", "deny")
            return decision == "permit", None

    checker = CountingChecker()
    g = _guard(cache=cache, obligation_checker=checker)

    # First call populates the cache; second should hit it.
    batch = [(_S, Action("read"), _R, _CTX), (_S, Action("read"), _R, _CTX)]
    results = await g.evaluate_batch_async(batch)

    assert results[0].allowed is True
    assert results[1].allowed is True
    # With cache, the underlying policy eval happens once; obligation checker
    # still called per request (cache stores raw decision, not final Decision).
    assert checker.calls == 2


# ---------------------------------------------------------------------------
# evaluate_batch_sync — core behaviour
# ---------------------------------------------------------------------------


def test_batch_sync_empty_returns_empty_list():
    """Sync wrapper: empty input returns []."""
    g = _guard()
    result = g.evaluate_batch_sync([])
    assert result == []


def test_batch_sync_single_request_permit():
    """Sync wrapper: single permit request."""
    g = _guard()
    results = g.evaluate_batch_sync([(_S, Action("read"), _R, _CTX)])
    assert len(results) == 1
    assert results[0].allowed is True


def test_batch_sync_single_request_deny():
    """Sync wrapper: single deny request."""
    g = _guard()
    results = g.evaluate_batch_sync([(_S, Action("delete"), _R, _CTX)])
    assert len(results) == 1
    assert results[0].allowed is False


def test_batch_sync_multiple_order_preserved():
    """Sync wrapper: order preserved across mixed results."""
    g = _guard()
    batch = [
        (_S, Action("read"), _R, _CTX),
        (_S, Action("delete"), _R, _CTX),
        (_S, Action("write"), _R, None),
    ]
    results = g.evaluate_batch_sync(batch)

    assert len(results) == 3
    assert results[0].allowed is True
    assert results[1].allowed is False
    assert results[2].allowed is False


def test_batch_sync_context_none_is_accepted():
    """Sync wrapper: None context accepted."""
    g = _guard()
    results = g.evaluate_batch_sync([(_S, Action("read"), _R, None)])
    assert results[0].allowed is True


def test_batch_sync_returns_list_of_decision_objects():
    """Result type is list[Decision]."""
    from rbacx.core.decision import Decision

    g = _guard()
    results = g.evaluate_batch_sync([(_S, Action("read"), _R, _CTX)])
    assert isinstance(results, list)
    assert all(isinstance(d, Decision) for d in results)


# ---------------------------------------------------------------------------
# evaluate_batch_sync — running-loop path (ThreadPoolExecutor)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_batch_sync_inside_running_loop_uses_executor():
    """
    Calling evaluate_batch_sync while an event loop is already running
    delegates to the class-level ThreadPoolExecutor (same strategy as
    evaluate_sync).
    """
    g = _guard()
    batch = [
        (_S, Action("read"), _R, _CTX),
        (_S, Action("delete"), _R, _CTX),
    ]
    # Called from inside an async test — loop is active.
    results = g.evaluate_batch_sync(batch)
    assert len(results) == 2
    assert results[0].allowed is True
    assert results[1].allowed is False


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_batch_async_tuple_with_all_none_context():
    """A batch where every context is None must work end-to-end."""
    g = _guard()
    batch = [
        (_S, Action("read"), _R, None),
        (_S, Action("delete"), _R, None),
    ]
    results = await g.evaluate_batch_async(batch)
    assert results[0].allowed is True
    assert results[1].allowed is False


@pytest.mark.asyncio
async def test_batch_async_with_policyset():
    """Batch evaluation works correctly with a policy set (not just a single policy)."""
    policyset = {
        "algorithm": "deny-overrides",
        "policies": [
            {
                "id": "p1",
                "algorithm": "deny-overrides",
                "rules": [
                    {
                        "id": "r1",
                        "effect": "permit",
                        "actions": ["read"],
                        "resource": {"type": "doc"},
                    }
                ],
            }
        ],
    }
    g = Guard(policyset)
    s = Subject(id="u")
    resource = Resource(type="doc", id="1")

    results = await g.evaluate_batch_async(
        [
            (s, Action("read"), resource, None),
            (s, Action("write"), resource, None),
        ]
    )

    assert results[0].allowed is True
    assert results[1].allowed is False


@pytest.mark.asyncio
async def test_batch_async_rule_id_per_decision():
    """Each Decision in the batch carries the correct matched rule_id."""
    g = _guard()
    results = await g.evaluate_batch_async(
        [
            (_S, Action("read"), _R, _CTX),
            (_S, Action("delete"), _R, _CTX),
        ]
    )
    assert results[0].rule_id == "permit-read"
    assert results[1].rule_id == "deny-delete"


@pytest.mark.asyncio
async def test_batch_async_exception_propagates():
    """
    If _evaluate_core_async raises for one request the whole gather
    propagates the exception (fail-fast semantics).
    """

    async def _boom(self, *args, **kwargs):
        raise RuntimeError("injected failure")

    original = Guard._evaluate_core_async
    Guard._evaluate_core_async = _boom  # type: ignore[method-assign]
    try:
        g = _guard()
        with pytest.raises(RuntimeError, match="injected failure"):
            await g.evaluate_batch_async([(_S, Action("read"), _R, None)])
    finally:
        Guard._evaluate_core_async = original  # type: ignore[method-assign]


@pytest.mark.asyncio
async def test_batch_async_requests_run_concurrently():
    """
    Verify that requests are submitted concurrently: a batch of N sequential-
    sleep coroutines should finish faster than N * sleep_time.
    """
    import time

    original_core = Guard._evaluate_core_async
    sleep_sec = 0.05

    async def _slow_core(self, subject, action, resource, context, *, explain=False):
        await asyncio.sleep(sleep_sec)
        return await original_core(self, subject, action, resource, context, explain=explain)

    Guard._evaluate_core_async = _slow_core  # type: ignore[method-assign]
    try:
        n = 5
        g = _guard()
        batch = [(_S, Action("read"), _R, None)] * n

        t0 = time.perf_counter()
        results = await g.evaluate_batch_async(batch)
        elapsed = time.perf_counter() - t0

        assert len(results) == n
        # Sequential would take n * sleep_sec; concurrent should be well under 2x
        assert elapsed < sleep_sec * n * 0.8, (
            f"Batch took {elapsed:.3f}s; expected < {sleep_sec * n * 0.8:.3f}s "
            "(requests should run concurrently)"
        )
    finally:
        Guard._evaluate_core_async = original_core  # type: ignore[method-assign]
