import rbacx.core.cache as cache_mod
from rbacx.core.cache import DefaultInMemoryCache
from rbacx.core.engine import Guard


def test_normalize_env_fallback_to_repr_on_circular_reference():
    """
    Covers the fallback branch in Guard._normalize_env_for_cache:
    json.dumps raises on circular references even with default=str,
    so the method must return repr(env).
    """
    env = {}
    env["self"] = env  # circular reference -> ValueError in json.dumps
    s = Guard._normalize_env_for_cache(env)
    assert s == repr(env)
    assert "{...}" in s  # sanity check for recursive repr


def test__purge_expired_unlocked_removes_expired_prefix(monkeypatch):
    """
    Directly exercise DefaultInMemoryCache._purge_expired_unlocked()
    to cover the scan loop and the deletion loop.
    """
    # Controlled monotonic time
    t = {"now": 0.0}

    def fake_monotonic():
        return t["now"]

    monkeypatch.setattr(cache_mod.time, "monotonic", fake_monotonic)

    c = DefaultInMemoryCache(maxsize=16)
    # Insert three entries: two quickly expiring, one long-lived
    c.set("a", 1, ttl=1)  # expires at 1
    c.set("b", 2, ttl=10)  # expires at 10
    c.set("c", 3, ttl=1)  # expires at 1

    # Advance time past the short TTLs
    t["now"] = 2.0

    # Call the internal purge under lock to respect its contract
    with c._lock:  # white-box: cover internal helper
        c._purge_expired_unlocked()

    # The two expired keys should be gone; the long-lived key should remain
    assert "a" not in c._data
    assert "c" not in c._data
    assert "b" in c._data


def test_set_triggers_opportunistic_purge_of_expired(monkeypatch):
    """
    Cover the call site in DefaultInMemoryCache.set() that invokes
    _purge_expired_unlocked() and removes expired entries.
    """
    # Controlled monotonic time
    t = {"now": 0.0}

    def fake_monotonic():
        return t["now"]

    monkeypatch.setattr(cache_mod.time, "monotonic", fake_monotonic)

    c = DefaultInMemoryCache(maxsize=256)

    # Seed a bunch of soon-to-expire entries (more than 128 to exercise prefix slicing)
    for i in range(140):
        c.set(f"e{i}", i, ttl=1)  # expires at 1

    # Advance beyond the TTL so they are expired
    t["now"] = 5.0

    # Adding a new key should opportunistically purge expired ones
    c.set("fresh", "x")

    # At least the earliest expired entries from the scanned prefix must be gone
    assert "e0" not in c._data
    assert "e1" not in c._data
    assert "fresh" in c._data
