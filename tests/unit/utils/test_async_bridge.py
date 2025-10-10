import asyncio
import concurrent.futures
import threading

import pytest

# Import the module-under-test from your project.
from rbacx.core.helpers import _await_compat, maybe_await, resolve_awaitable_in_worker


@pytest.mark.asyncio
async def test__await_compat_awaits_any_awaitable():
    """
    Covers line 16: `return await x`.
    We pass a real awaitable and ensure the awaited value is returned.
    """

    async def coro():
        await asyncio.sleep(0)
        return "ok"

    # Pass a coroutine object (awaitable) and make sure _await_compat awaits it.
    result = await _await_compat(coro())
    assert result == "ok"


def _start_loop_in_thread():
    """
    Start a brand-new event loop in a dedicated thread and return (loop, thread).
    The loop must be running on its own thread for run_coroutine_threadsafe().
    """
    loop = asyncio.new_event_loop()
    ready = threading.Event()

    def _runner():
        asyncio.set_event_loop(loop)
        ready.set()
        loop.run_forever()

    th = threading.Thread(target=_runner, name="test-loop-thread", daemon=True)
    th.start()
    ready.wait(5)
    return loop, th


# NEW: drain helper to cancel/await all pending tasks in that loop
async def _drain_pending_in_loop():
    # enumerate *inside* the loop
    cur = asyncio.get_running_loop()
    tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task(cur)]
    for t in tasks:
        t.cancel()
    if tasks:
        # Gather and swallow exceptions (e.g., CancelledError)
        await asyncio.gather(*tasks, return_exceptions=True)


def _stop_loop(loop, thread):
    # 1) Drain pending tasks in the foreign loop
    try:
        # We must submit the coroutine into that running loop.
        fut = asyncio.run_coroutine_threadsafe(_drain_pending_in_loop(), loop)
        fut.result(timeout=1)
    except Exception:
        # Best-effort: even if draining fails, continue shutdown.
        pass

    # 2) Stop and join the thread
    if loop.is_running():
        loop.call_soon_threadsafe(loop.stop)
    thread.join(timeout=5)

    # 3) Close the loop
    try:
        loop.close()
    except RuntimeError:
        pass


def test_resolve_awaitable_in_worker_runs_on_foreign_loop_and_returns_value():
    """
    Covers lines 30–33: isawaitable-branch + run_coroutine_threadsafe + result(timeout).
    We submit a coroutine to an already-running event loop on another thread and
    obtain its return value via the returned Future's .result(timeout=...).
    """
    loop, th = _start_loop_in_thread()
    try:

        async def compute():
            await asyncio.sleep(0)
            return 123

        out = resolve_awaitable_in_worker(compute(), loop, timeout=2.0)
        assert out == 123
    finally:
        _stop_loop(loop, th)


def test_resolve_awaitable_in_worker_non_awaitable_returns_as_is():
    """
    Covers the `return x` in the else-branch (line 33).
    Passing a non-awaitable must return the value unchanged.
    """
    assert resolve_awaitable_in_worker(42, loop=None) == 42


def test_resolve_awaitable_in_worker_timeout_raises():
    """
    Also exercises lines 30–32: the Future is created via run_coroutine_threadsafe,
    then .result(timeout=...) raises concurrent.futures.TimeoutError if the coroutine
    does not finish in time.

    IMPORTANT: the pending task is drained in _stop_loop() to avoid the warning
    "Task was destroyed but it is pending!".
    """
    loop, th = _start_loop_in_thread()
    try:
        event = asyncio.Event()

        async def never_signals():
            await event.wait()
            return "unreachable"

        with pytest.raises(concurrent.futures.TimeoutError):
            resolve_awaitable_in_worker(never_signals(), loop, timeout=0.01)
    finally:
        _stop_loop(loop, th)


@pytest.mark.asyncio
async def test_maybe_await_smoke_for_completeness():
    """
    A small sanity check around maybe_await(...) so tests remain future-proof.
    This doesn't target your requested lines but protects the public helper.
    """

    async def coro():
        await asyncio.sleep(0)
        return "done"

    assert await maybe_await(coro()) == "done"
    assert await maybe_await("plain") == "plain"
