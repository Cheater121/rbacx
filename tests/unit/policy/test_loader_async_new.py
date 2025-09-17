import asyncio
import json

import pytest

import rbacx.policy.loader as loader_mod
from rbacx.core.engine import Guard
from rbacx.policy.loader import HotReloader

HAS_ASYNC = hasattr(HotReloader, "check_and_reload_async")


# ------------------------------- test doubles ---------------------------------


class AsyncSource:
    """Async PolicySource with controllable ETag and policy."""

    def __init__(self, etag="v1", policy=None, fail_mode=None):
        """
        fail_mode:
            None           -> normal
            "json_error"   -> load() raises JSONDecodeError
            "not_found"    -> load() raises FileNotFoundError
        """
        self._etag = etag
        self._policy = policy if policy is not None else {"rules": []}
        self.fail_mode = fail_mode
        self.etag_calls = 0
        self.load_calls = 0

    async def etag(self):
        self.etag_calls += 1
        await asyncio.sleep(0)
        return self._etag

    async def load(self):
        self.load_calls += 1
        await asyncio.sleep(0)
        if self.fail_mode == "json_error":
            # Construct a minimal JSONDecodeError
            raise json.JSONDecodeError("bad", doc="", pos=0)
        if self.fail_mode == "not_found":
            raise FileNotFoundError("missing")
        return self._policy

    # Helpers to mutate state
    def set(self, *, etag=None, policy=None):
        if etag is not None:
            self._etag = etag
        if policy is not None:
            self._policy = policy


class SyncSource:
    """Sync PolicySource with controllable ETag and policy."""

    def __init__(self, etag="v1", policy=None, fail_mode=None):
        self._etag = etag
        self._policy = policy if policy is not None else {"rules": []}
        self.fail_mode = fail_mode
        self.etag_calls = 0
        self.load_calls = 0

    def etag(self):
        self.etag_calls += 1
        return self._etag

    def load(self):
        self.load_calls += 1
        if self.fail_mode == "json_error":
            raise json.JSONDecodeError("bad", doc="", pos=0)
        if self.fail_mode == "not_found":
            raise FileNotFoundError("missing")
        return self._policy

    def set(self, *, etag=None, policy=None):
        if etag is not None:
            self._etag = etag
        if policy is not None:
            self._policy = policy


# ---------------------------------- tests -------------------------------------


@pytest.mark.asyncio
@pytest.mark.skipif(not HAS_ASYNC, reason="new async reloader API is not available in this build")
async def test_async_source_basic_reload_flow():
    """
    With async PolicySource:
      - First call loads policy when ETag differs from primed value.
      - Second call with same ETag is a no-op.
      - After ETag change, policy reloads again.
    """
    g = Guard(policy={})
    src = AsyncSource(etag="v1", policy={"rules": [{"id": "r1"}]})
    r = HotReloader(g, src, initial_load=False)

    # On __init__, last_etag is None because etag() is async and not primed.
    assert r.last_etag is None

    # First check loads
    changed = await r.check_and_reload_async()
    assert changed is True
    assert g.policy == {"rules": [{"id": "r1"}]}
    assert r.last_etag == "v1"

    # Same ETag -> no reload
    changed = await r.check_and_reload_async()
    assert changed is False

    # Change ETag + policy -> reload
    src.set(etag="v2", policy={"rules": [{"id": "r2"}]})
    changed = await r.check_and_reload_async()
    assert changed is True
    assert g.policy == {"rules": [{"id": "r2"}]}
    assert r.last_etag == "v2"


@pytest.mark.asyncio
@pytest.mark.skipif(not HAS_ASYNC, reason="new async reloader API is not available in this build")
async def test_force_reload_bypasses_etag_check_async():
    g = Guard(policy={})
    src = AsyncSource(etag="v1", policy={"rules": [{"id": "r1"}]})
    r = HotReloader(g, src, initial_load=False)

    # Prime state by loading once
    await r.check_and_reload_async()
    assert g.policy == {"rules": [{"id": "r1"}]}

    # Keep same ETag but change policy; force=True must apply it
    src.set(policy={"rules": [{"id": "forced"}]})
    changed = await r.check_and_reload_async(force=True)
    assert changed is True
    assert g.policy == {"rules": [{"id": "forced"}]}


@pytest.mark.asyncio
@pytest.mark.skipif(not HAS_ASYNC, reason="new async reloader API is not available in this build")
async def test_error_paths_set_suppression_and_backoff(monkeypatch):
    """
    JSONDecodeError and FileNotFoundError should register error and set suppression window.
    """
    g = Guard(policy={})
    src = AsyncSource(etag="v1", policy={"rules": [{"id": "r"}]}, fail_mode="json_error")
    r = HotReloader(g, src, initial_load=False, backoff_min=2.0, backoff_max=30.0, jitter_ratio=0.0)

    # Freeze time and jitter for deterministic assertions
    now_ptr = {"t": 1000.0}

    def fake_time():
        return now_ptr["t"]

    monkeypatch.setattr(loader_mod.time, "time", fake_time)
    monkeypatch.setattr(loader_mod.random, "uniform", lambda a, b: 0.0)

    changed = await r.check_and_reload_async()
    assert changed is False
    assert r.last_error is not None
    # suppression should be now + backoff (no jitter) >= 1002.0
    assert r.suppressed_until >= 1002.0

    # Another attempt within suppression -> early return False
    changed2 = await r.check_and_reload_async()
    assert changed2 is False

    # Move time beyond suppression and switch to not_found path
    now_ptr["t"] = r.suppressed_until + 0.1
    src.fail_mode = "not_found"
    changed3 = await r.check_and_reload_async()
    assert changed3 is False
    assert isinstance(r.last_error, FileNotFoundError)


@pytest.mark.asyncio
@pytest.mark.skipif(not HAS_ASYNC, reason="new async reloader API is not available in this build")
async def test_sync_wrapper_inside_running_loop_works():
    """
    Calling the sync wrapper while a loop is running should still work
    (the reloader executes the async core in a helper thread).
    """
    g = Guard(policy={})
    src = AsyncSource(etag="v1", policy={"rules": [{"id": "r"}]})
    r = HotReloader(g, src, initial_load=False)

    # Call sync wrapper within active loop
    changed = r.check_and_reload(force=False)
    assert changed is True
    assert g.policy == {"rules": [{"id": "r"}]}


def test_sync_source_and_start_initial_load():
    """
    With a sync PolicySource, the legacy sync path works and start(initial_load=True)
    performs a synchronous initial reload before the background thread starts.
    """
    g = Guard(policy={})
    src = SyncSource(etag="v1", policy={"rules": [{"id": "r"}]})
    r = HotReloader(g, src, initial_load=False)

    # Since etag() is sync and initial_load=False, constructor primes last_etag,
    # so first check should be a NO-OP unless forced or ETag changes.
    assert r.last_etag == "v1"
    assert r.check_and_reload() is False

    # start() with initial_load=True performs one synchronous load
    r.start(initial_load=True, force_initial=True)
    try:
        assert g.policy == {"rules": [{"id": "r"}]}
    finally:
        r.stop()


@pytest.mark.asyncio
@pytest.mark.skipif(not HAS_ASYNC, reason="new async reloader API is not available in this build")
async def test_async_then_noop_same_etag():
    g = Guard(policy={})
    src = AsyncSource(etag="e1", policy={"rules": [{"id": "x"}]})
    r = HotReloader(g, src, initial_load=False)

    # First load
    assert await r.check_and_reload_async() is True
    assert g.policy == {"rules": [{"id": "x"}]}

    # No changes -> NO-OP
    assert await r.check_and_reload_async() is False


def test_properties_threadsafe_read():
    """Basic smoke test for property access under lock."""
    g = Guard(policy={})
    src = SyncSource(etag="k", policy={"rules": []})
    r = HotReloader(g, src)

    # Accessors should work and not raise
    _ = r.last_etag
    _ = r.last_reload_at
    _ = r.last_error
    _ = r.suppressed_until


@pytest.mark.asyncio
@pytest.mark.skipif(not HAS_ASYNC, reason="new async reloader API is not available in this build")
async def test_force_reload_sync_wrapper_delegates():
    """Sync wrapper with force=True should delegate and apply policy even if ETag unchanged."""
    g = Guard(policy={})
    src = AsyncSource(etag="a1", policy={"rules": [{"id": "a"}]})
    r = HotReloader(g, src)

    # Initial application
    assert r.check_and_reload(force=True) is True
    assert g.policy == {"rules": [{"id": "a"}]}

    # Change policy but keep same ETag; force=True again to apply
    src.set(policy={"rules": [{"id": "b"}]})
    assert r.check_and_reload(force=True) is True
    assert g.policy == {"rules": [{"id": "b"}]}
