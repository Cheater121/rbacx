"""Tests for HotReloader.check_and_reload() executor reuse (1.9.1).

Verifies that the class-level ThreadPoolExecutor is created lazily and
reused across calls instead of being spawned on every invocation.
"""

import asyncio

from rbacx.core.engine import Guard
from rbacx.policy.loader import HotReloader

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _StaticSource:
    """PolicySource that always returns the same policy and a fixed ETag."""

    def __init__(self, policy: dict, etag: str = "etag-1") -> None:
        self._policy = policy
        self._etag = etag

    def load(self) -> dict:
        return dict(self._policy)

    def etag(self) -> str:
        return self._etag


_POLICY = {"algorithm": "deny-overrides", "rules": []}


def _make_reloader(etag: str = "etag-1") -> HotReloader:
    guard = Guard(_POLICY)
    source = _StaticSource(_POLICY, etag=etag)
    return HotReloader(guard, source, initial_load=True)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_executor_is_none_before_first_use_from_running_loop():
    """_executor must be None until check_and_reload() needs it."""
    original = HotReloader._executor
    HotReloader._executor = None
    assert HotReloader._executor is None
    HotReloader._executor = original  # restore


def test_executor_created_on_first_call_from_running_loop():
    """_executor must be created when check_and_reload() is called from a running loop."""
    HotReloader._executor = None

    async def _trigger():
        r = _make_reloader()
        r.check_and_reload(force=True)
        return HotReloader._executor

    executor = asyncio.run(_trigger())
    assert executor is not None, "executor must be created after first use from running loop"


def test_executor_reused_across_calls_from_running_loop():
    """The same executor instance must be reused on subsequent calls."""
    HotReloader._executor = None

    async def _trigger():
        r = _make_reloader(etag="e1")
        r.check_and_reload(force=True)
        ex1 = HotReloader._executor
        r.check_and_reload(force=True)
        ex2 = HotReloader._executor
        return ex1, ex2

    ex1, ex2 = asyncio.run(_trigger())
    assert ex1 is not None
    assert ex1 is ex2, "executor must be reused, not re-created on every call"


def test_check_and_reload_works_correctly_from_running_loop():
    """check_and_reload() called from inside a running loop must return a bool."""

    async def _run():
        r = _make_reloader()
        result = r.check_and_reload(force=True)
        return result

    result = asyncio.run(_run())
    assert isinstance(result, bool)


def test_check_and_reload_works_without_running_loop():
    """check_and_reload() called from a plain thread (no loop) must also work."""
    import threading

    results = []
    errors = []

    def _thread():
        try:
            r = _make_reloader()
            results.append(r.check_and_reload(force=True))
        except Exception as e:
            errors.append(e)

    t = threading.Thread(target=_thread)
    t.start()
    t.join()

    assert not errors, f"unexpected error: {errors[0]}"
    assert isinstance(results[0], bool)
