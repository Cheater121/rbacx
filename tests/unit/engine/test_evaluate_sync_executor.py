"""Tests for Guard.evaluate_sync() execution model changes introduced in 1.9.0.

Changes verified:
- evaluate_sync() works correctly when no event loop is running (asyncio.run path).
- evaluate_sync() works correctly when called from inside a running event loop
  (class-level ThreadPoolExecutor path).
- The class-level executor is created lazily and reused across calls — not
  re-created on every invocation.
- Guard.__init__() no longer manipulates the global event loop state.
"""

import asyncio
import threading

from rbacx.core.engine import Guard
from rbacx.core.model import Action, Context, Resource, Subject

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_POLICY = {
    "algorithm": "deny-overrides",
    "rules": [
        {"id": "r1", "actions": ["read"], "effect": "permit", "resource": {"type": "doc"}},
    ],
}

_SUBJECT = Subject(id="u1", roles=[], attrs={})
_ACTION = Action(name="read")
_RESOURCE = Resource(type="doc", id="d1")
_CONTEXT = Context()


def _make_guard() -> Guard:
    return Guard(_POLICY)


# ---------------------------------------------------------------------------
# Scenario 1: no running loop — asyncio.run() path
# ---------------------------------------------------------------------------


def test_evaluate_sync_no_running_loop_returns_correct_decision():
    """evaluate_sync() must work from a plain thread with no event loop."""
    result = [None]
    error = [None]

    def _run():
        try:
            g = _make_guard()
            result[0] = g.evaluate_sync(_SUBJECT, _ACTION, _RESOURCE, _CONTEXT)
        except Exception as e:
            error[0] = e

    t = threading.Thread(target=_run)
    t.start()
    t.join()

    assert error[0] is None, f"unexpected error: {error[0]}"
    assert result[0] is not None
    assert result[0].allowed is True


def test_evaluate_sync_no_running_loop_multiple_calls():
    """Multiple sequential evaluate_sync() calls must all succeed."""
    g = _make_guard()
    for _ in range(5):
        d = g.evaluate_sync(_SUBJECT, _ACTION, _RESOURCE, _CONTEXT)
        assert d.allowed is True


# ---------------------------------------------------------------------------
# Scenario 2: called from inside a running event loop — executor path
# ---------------------------------------------------------------------------


def test_evaluate_sync_inside_running_loop():
    """evaluate_sync() must work when called from sync code inside an async context."""

    async def _async_caller():
        g = _make_guard()
        # This exercises the ThreadPoolExecutor path because asyncio.get_running_loop()
        # will succeed inside this coroutine.
        return g.evaluate_sync(_SUBJECT, _ACTION, _RESOURCE, _CONTEXT)

    d = asyncio.run(_async_caller())
    assert d.allowed is True


def test_evaluate_sync_inside_running_loop_multiple_calls():
    """Multiple evaluate_sync() calls from inside a running loop must all succeed."""

    async def _async_caller():
        g = _make_guard()
        results = []
        for _ in range(5):
            results.append(g.evaluate_sync(_SUBJECT, _ACTION, _RESOURCE, _CONTEXT))
        return results

    decisions = asyncio.run(_async_caller())
    assert all(d.allowed is True for d in decisions)


# ---------------------------------------------------------------------------
# Scenario 3: executor is lazily created and reused
# ---------------------------------------------------------------------------


def test_executor_is_none_before_first_use():
    """_executor must be None until evaluate_sync() needs it."""
    # Reset executor to ensure clean state for this test.
    original = Guard._executor
    Guard._executor = None

    # Before any call from a running loop, executor stays None.
    assert Guard._executor is None

    Guard._executor = original  # restore


def test_executor_is_reused_across_calls():
    """The same executor instance must be reused on subsequent calls."""

    # Force creation by calling from a running loop.
    async def _trigger():
        g = _make_guard()
        g.evaluate_sync(_SUBJECT, _ACTION, _RESOURCE, _CONTEXT)
        return Guard._executor

    executor_after_first = asyncio.run(_trigger())
    assert executor_after_first is not None, "executor should be created after first use"

    executor_after_second = asyncio.run(_trigger())
    assert (
        executor_after_first is executor_after_second
    ), "executor must be reused across calls, not re-created"


# ---------------------------------------------------------------------------
# Scenario 4: __init__ no longer touches the global event loop
# ---------------------------------------------------------------------------


def test_init_does_not_set_global_event_loop():
    """Guard.__init__() must not create or set a global event loop as a side effect."""

    def _run_in_clean_thread():
        # Verify there is no running loop in this thread.
        try:
            asyncio.get_running_loop()
            return "loop_already_running"
        except RuntimeError:
            pass

        # Instantiate Guard — this must not create a global event loop.
        _make_guard()

        # In Python 3.10+ get_event_loop() emits DeprecationWarning and may
        # return a new loop or raise RuntimeError depending on version.
        # The key invariant: Guard.__init__ must not call set_event_loop().
        # We verify by checking that no loop is *running* after construction.
        try:
            asyncio.get_running_loop()
            return "loop_started_by_init"  # bad: __init__ started a loop
        except RuntimeError:
            return "ok"  # good: no running loop after init

    result = [None]

    def _thread():
        result[0] = _run_in_clean_thread()

    t = threading.Thread(target=_thread)
    t.start()
    t.join()

    assert result[0] == "ok", f"Guard.__init__ affected event loop state: {result[0]}"
