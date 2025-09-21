import threading
import time

import pytest

import rbacx.policy.loader as pl
from rbacx.core.engine import Guard
from rbacx.policy.loader import HotReloader

# -------------------- helpers --------------------


class _DummyGuard(Guard):
    # Wrap the real Guard but avoid heavy deps; default policy is minimal.
    def __init__(self):
        super().__init__({"rules": []})


# -------------------- 83–84: __init__ etag priming raises -> except path sets _last_etag=None --------------------


def test_init_etag_priming_exception_sets_last_etag_none():
    class Src:
        # Sync etag so __init__ tries to call it and hits the except
        def etag(self):
            raise RuntimeError("boom")

    g = _DummyGuard()
    r = HotReloader(g, Src(), initial_load=False)
    # When the etag() call raises during priming, last_etag must be None
    assert r.last_etag is None


# -------------------- 146–147: force path; etag() raises in inner try -> new_etag=None --------------------


@pytest.mark.asyncio
async def test_check_and_reload_async_force_etag_exception_sets_none():
    class Src:
        def __init__(self):
            self._loaded = False

        async def load(self):
            self._loaded = True
            return {"rules": []}

        # This will raise inside the inner try: except -> new_etag=None
        async def etag(self):
            raise RuntimeError("no-etag")

    g = _DummyGuard()
    r = HotReloader(g, Src(), initial_load=True)
    changed = await r.check_and_reload_async(force=True)
    assert changed is True
    assert r.last_etag is None


# -------------------- 187: refresh_if_needed() forwards to check_and_reload() --------------------


def test_refresh_if_needed_forwards_to_check_and_reload(monkeypatch):
    g = _DummyGuard()

    # dummy source never used here
    class Src:
        pass

    r = HotReloader(g, Src(), initial_load=True)
    called = {"ok": False}

    def fake_check_and_reload(*, force=False):
        called["ok"] = True
        return True

    monkeypatch.setattr(r, "check_and_reload", fake_check_and_reload, raising=False)
    assert r.refresh_if_needed() is True
    assert called["ok"] is True


# -------------------- 190: poll_once() forwards to check_and_reload() --------------------


def test_poll_once_forwards_to_check_and_reload(monkeypatch):
    g = _DummyGuard()

    class Src:
        pass

    r = HotReloader(g, Src(), initial_load=True)
    called = {"ok": False}

    def fake_check_and_reload(*, force=False):
        called["ok"] = True
        return False

    monkeypatch.setattr(r, "check_and_reload", fake_check_and_reload, raising=False)
    assert r.poll_once() is False
    assert called["ok"] is True


# -------------------- 213: start() returns early if a thread exists and is alive --------------------


def test_start_returns_early_when_thread_alive(monkeypatch):
    g = _DummyGuard()

    class Src:
        pass

    r = HotReloader(g, Src(), initial_load=True)

    class AliveThread:
        def is_alive(self):
            return True

    # Pre-install a "live" thread object so start() exits via early return
    r._thread = AliveThread()  # type: ignore[assignment]

    # If start() tried to create a real thread, we want to notice; make it fail loudly
    def fail_thread(*args, **kwargs):
        raise AssertionError("Thread() should not be called when _thread is alive")

    monkeypatch.setattr(threading, "Thread", fail_thread)
    r.start(interval=0.1)  # should NO-OP
    # No assertion error means the early-return branch executed


# -------------------- 233: stop() returns early when no thread is present --------------------


def test_stop_returns_early_when_no_thread():
    g = _DummyGuard()

    class Src:
        pass

    r = HotReloader(g, Src(), initial_load=True)

    # Ensure no thread set
    r._thread = None  # type: ignore[assignment]
    # Should simply return without errors
    r.stop(timeout=0.01)


# -------------------- 298: _run_loop honors suppress window (now < _suppress_until) --------------------


def test_run_loop_respects_suppress_until_and_exits_cleanly(monkeypatch):
    g = _DummyGuard()

    class Src:
        pass

    r = HotReloader(g, Src(), initial_load=True)

    # Make suppress window in the future so branch is taken
    with r._lock:
        r._suppress_until = time.time() + 5.0

    # Avoid random jitter affecting timing
    import rbacx.policy.loader as mod

    monkeypatch.setattr(mod.random, "uniform", lambda a, b: 0.0, raising=True)

    # Make check_and_reload lightweight
    called = {"cnt": 0}

    def fake_check_and_reload(*, force=False):
        called["cnt"] += 1
        return False

    monkeypatch.setattr(r, "check_and_reload", fake_check_and_reload, raising=False)

    # Run the loop in a dedicated thread and stop shortly after the first iteration
    t = threading.Thread(target=r._run_loop, args=(0.2,), daemon=True)
    t.start()
    # Give it a brief moment to run into the suppress branch
    time.sleep(0.05)
    r._stop_event.set()
    t.join(timeout=1.0)

    # It should have at least attempted a single check and then exited
    assert called["cnt"] >= 1
    assert not t.is_alive()


# ---------- cover 304–307: inner sleep loop takes the `remaining <= 0` break ----------
@pytest.mark.asyncio
async def test__run_loop_breaks_when_remaining_le_zero(monkeypatch):
    # Freeze jitter to 0 so sleep_for = base_interval.
    monkeypatch.setattr(pl.random, "uniform", lambda a, b: 0.0, raising=True)

    # Fake time sequence:
    # 1) now for computing 'now'                   -> 100.0
    # 2) time() for computing 'end = time() + sf' -> 100.0, so end = 100.2 (sf=min 0.2)
    # 3) time() inside inner while                -> 100.3 => remaining = -0.1 -> break
    seq = [100.0, 100.0, 100.3]
    idx = {"i": 0}

    def fake_time():
        i = idx["i"]
        idx["i"] = i + 1
        return seq[i] if i < len(seq) else seq[-1]

    monkeypatch.setattr(pl.time, "time", fake_time, raising=True)

    # Minimal guard/source; we don't want any real work in the loop.
    class Src:
        pass

    r = HotReloader(Guard({"rules": []}), Src(), initial_load=True)

    # Make the periodic check a no-op (faster & deterministic).
    monkeypatch.setattr(r, "check_and_reload", lambda **kw: False, raising=False)

    # Run the loop in a thread; it should enter the inner while once and hit the break.
    t = threading.Thread(target=r._run_loop, args=(0.2,), daemon=True)
    t.start()

    # Give the loop a moment to run, then stop and join.
    time.sleep(0.05)
    r._stop_event.set()
    t.join(timeout=1.0)

    assert not t.is_alive()
