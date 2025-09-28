import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from rbacx.core.cache import DefaultInMemoryCache


def test_set_get_roundtrip():
    c = DefaultInMemoryCache(maxsize=8)
    c.set("k", 123, ttl=5)
    assert c.get("k") == 123


def test_get_miss_returns_none():
    c = DefaultInMemoryCache(maxsize=8)
    assert c.get("absent") is None


def test_delete_removes_key():
    c = DefaultInMemoryCache(maxsize=8)
    c.set("k", "v", ttl=5)
    c.delete("k")
    assert c.get("k") is None


def test_clear_flushes_all():
    c = DefaultInMemoryCache(maxsize=8)
    for i in range(5):
        c.set(f"k{i}", i, ttl=5)
    c.clear()
    for i in range(5):
        assert c.get(f"k{i}") is None


def test_ttl_not_expired(monkeypatch):
    c = DefaultInMemoryCache(maxsize=8)
    base = 1000.0

    def fake_monotonic():
        return fake_monotonic.t

    fake_monotonic.t = base

    monkeypatch.setattr(time, "monotonic", fake_monotonic, raising=True)

    c.set("k", "v", ttl=2)
    assert c.get("k") == "v"  # no time shift


def test_ttl_expired(monkeypatch):
    c = DefaultInMemoryCache(maxsize=8)
    base = 1000.0

    def fake_monotonic():
        return fake_monotonic.t

    fake_monotonic.t = base

    monkeypatch.setattr(time, "monotonic", fake_monotonic, raising=True)

    c.set("k", "v", ttl=1)
    fake_monotonic.t = base + 1.001
    assert c.get("k") is None


def test_lru_evicts_least_recent():
    c = DefaultInMemoryCache(maxsize=2)
    c.set("a", 1)
    c.set("b", 2)
    # access a to make it MRU
    assert c.get("a") == 1
    # inserting c should evict b
    c.set("c", 3)
    assert c.get("b") is None
    assert c.get("a") == 1
    assert c.get("c") == 3


def test_expired_key_removed_lazily(monkeypatch):
    c = DefaultInMemoryCache(maxsize=8)
    base = 1000.0

    def fake_monotonic():
        return fake_monotonic.t

    fake_monotonic.t = base
    monkeypatch.setattr(time, "monotonic", fake_monotonic, raising=True)

    c.set("k", "v", ttl=1)
    fake_monotonic.t = base + 2.5
    # first get returns None and purges lazily
    assert c.get("k") is None
    # a second get should not find the key at all (already removed)
    assert c.get("k") is None


def test_thread_safety_basic():
    c = DefaultInMemoryCache(maxsize=64)

    def worker(i: int):
        c.set(f"k{i}", i, ttl=1)
        _ = c.get(f"k{i}")
        if i % 2 == 0:
            c.delete(f"k{i}")

    with ThreadPoolExecutor(max_workers=8) as ex:
        for i in range(50):
            ex.submit(worker, i)

    # last write dominates for one surviving key
    c.set("z", 1)
    c.set("z", 2)
    assert c.get("z") == 2


@pytest.mark.parametrize("ttl", [0, -1, None])
def test_set_with_zero_or_negative_ttl(ttl):
    c = DefaultInMemoryCache(maxsize=8)
    c.set("k", "v", ttl=ttl)  # treated as no-expiry
    assert c.get("k") == "v"


def test_set_over_capacity_eviction_loops_until_within_maxsize():
    c = DefaultInMemoryCache(maxsize=1)
    c.set("a", 1)
    c.set("b", 2)
    c.set("c", 3)
    assert c.get("a") is None
    assert c.get("b") is None
    assert c.get("c") == 3
