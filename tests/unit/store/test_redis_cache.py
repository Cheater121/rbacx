"""Unit tests for RedisCache — uses a stub Redis client, no real Redis needed."""

import json
from typing import Any

from rbacx.core.redis_cache import RedisCache

# ---------------------------------------------------------------------------
# Stub Redis client
# ---------------------------------------------------------------------------


class _StubRedis:
    """Minimal in-memory Redis stub that tracks calls."""

    def __init__(self, initial: dict[str, bytes] | None = None) -> None:
        self._data: dict[str, bytes] = {}
        if initial:
            self._data.update(initial)
        self.calls: list[tuple[str, Any]] = []

    def get(self, key: str) -> bytes | None:
        self.calls.append(("get", key))
        return self._data.get(key)

    def set(self, key: str, value: str) -> None:
        self.calls.append(("set", key, value))
        self._data[key] = value.encode() if isinstance(value, str) else value

    def setex(self, key: str, ttl: int, value: str) -> None:
        self.calls.append(("setex", key, ttl, value))
        self._data[key] = value.encode() if isinstance(value, str) else value

    def delete(self, *keys: str) -> None:
        self.calls.append(("delete", keys))
        for k in keys:
            self._data.pop(k, None)

    def scan_iter(self, pattern: str):
        self.calls.append(("scan_iter", pattern))
        prefix = pattern.rstrip("*")
        return [k for k in self._data if k.startswith(prefix)]


class _RaisingRedis:
    """Stub that raises on every operation."""

    def get(self, key):
        raise ConnectionError("Redis down")

    def set(self, key, value):
        raise ConnectionError("Redis down")

    def setex(self, key, ttl, value):
        raise ConnectionError("Redis down")

    def delete(self, *keys):
        raise ConnectionError("Redis down")

    def scan_iter(self, pattern):
        raise ConnectionError("Redis down")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _enc(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _cache(stub=None, prefix="rbacx:", default_ttl=None):
    return RedisCache(stub or _StubRedis(), prefix=prefix, default_ttl=default_ttl)


# ---------------------------------------------------------------------------
# get
# ---------------------------------------------------------------------------


def test_get_existing_key_returns_value():
    payload = {"decision": "permit", "rule_id": "r1", "obligations": []}
    stub = _StubRedis({"rbacx:mykey": _enc(payload)})
    c = _cache(stub)
    assert c.get("mykey") == payload


def test_get_missing_key_returns_none():
    c = _cache(_StubRedis())
    assert c.get("nonexistent") is None


def test_get_applies_prefix():
    stub = _StubRedis({"rbacx:k1": _enc({"x": 1})})
    c = _cache(stub, prefix="rbacx:")
    assert c.get("k1") == {"x": 1}
    # wrong prefix → miss
    assert c.get("rbacx:k1") is None


def test_get_redis_error_returns_none():
    c = RedisCache(_RaisingRedis())
    assert c.get("any") is None


def test_get_invalid_json_returns_none():
    stub = _StubRedis({"rbacx:bad": b"not-json{"})
    c = _cache(stub)
    assert c.get("bad") is None


def test_get_none_value_returns_none():
    """Redis returns None (key not found) → get returns None."""
    stub = _StubRedis()
    c = _cache(stub)
    assert c.get("missing") is None


# ---------------------------------------------------------------------------
# set
# ---------------------------------------------------------------------------


def test_set_with_explicit_ttl_uses_setex():
    stub = _StubRedis()
    c = _cache(stub)
    payload = {"decision": "permit"}
    c.set("k", payload, ttl=60)

    setex_calls = [(name, *args) for name, *args in stub.calls if name == "setex"]
    assert len(setex_calls) == 1
    name, key, ttl, value = setex_calls[0]
    assert key == "rbacx:k"
    assert ttl == 60
    assert json.loads(value) == payload


def test_set_without_ttl_uses_set():
    stub = _StubRedis()
    c = _cache(stub)
    c.set("k", {"decision": "deny"}, ttl=None)

    set_calls = [args for name, *args in stub.calls if name == "set"]
    assert len(set_calls) == 1
    assert set_calls[0][0] == "rbacx:k"


def test_set_default_ttl_used_when_no_explicit_ttl():
    stub = _StubRedis()
    c = _cache(stub, default_ttl=120)
    c.set("k", {"x": 1})

    setex_calls = [(name, *args) for name, *args in stub.calls if name == "setex"]
    assert len(setex_calls) == 1
    _, _, ttl, _ = setex_calls[0]
    assert ttl == 120


def test_set_explicit_ttl_overrides_default_ttl():
    stub = _StubRedis()
    c = _cache(stub, default_ttl=120)
    c.set("k", {"x": 1}, ttl=30)

    setex_calls = [(name, *args) for name, *args in stub.calls if name == "setex"]
    assert setex_calls[0][2] == 30  # explicit wins


def test_set_zero_ttl_uses_set_not_setex():
    """ttl=0 is treated as 'no expiry' — uses SET not SETEX."""
    stub = _StubRedis()
    c = _cache(stub)
    c.set("k", {"x": 1}, ttl=0)

    set_calls = [args for name, *args in stub.calls if name == "set"]
    setex_calls = [args for name, *args in stub.calls if name == "setex"]
    assert len(set_calls) == 1
    assert len(setex_calls) == 0


def test_set_redis_error_is_swallowed():
    c = RedisCache(_RaisingRedis())
    c.set("k", {"x": 1}, ttl=60)  # must not raise


def test_set_value_round_trips():
    """Value stored by set can be retrieved by get."""
    stub = _StubRedis()
    c = _cache(stub)
    payload = {"decision": "permit", "rule_id": "r1", "obligations": [], "trace": None}
    c.set("key", payload, ttl=300)
    assert c.get("key") == payload


# ---------------------------------------------------------------------------
# delete
# ---------------------------------------------------------------------------


def test_delete_removes_key():
    payload = {"decision": "permit"}
    stub = _StubRedis({"rbacx:k": _enc(payload)})
    c = _cache(stub)
    c.delete("k")
    assert c.get("k") is None


def test_delete_applies_prefix():
    stub = _StubRedis()
    c = _cache(stub, prefix="myapp:")
    c.delete("somekey")
    delete_calls = [args for name, *args in stub.calls if name == "delete"]
    assert delete_calls[0][0] == ("myapp:somekey",)


def test_delete_redis_error_is_swallowed():
    c = RedisCache(_RaisingRedis())
    c.delete("k")  # must not raise


# ---------------------------------------------------------------------------
# clear
# ---------------------------------------------------------------------------


def test_clear_removes_all_prefixed_keys():
    stub = _StubRedis(
        {
            "rbacx:a": _enc({"x": 1}),
            "rbacx:b": _enc({"x": 2}),
            "other:c": _enc({"x": 3}),  # different prefix — must survive
        }
    )
    c = _cache(stub)
    c.clear()

    assert c.get("a") is None
    assert c.get("b") is None
    # other prefix untouched
    assert stub._data.get("other:c") is not None


def test_clear_empty_store_is_noop():
    stub = _StubRedis()
    c = _cache(stub)
    c.clear()  # must not raise; no delete call with empty keys
    delete_calls = [args for name, *args in stub.calls if name == "delete"]
    assert delete_calls == []


def test_clear_uses_scan_not_flushdb():
    """clear() must use SCAN, never FLUSHDB."""
    stub = _StubRedis({"rbacx:x": _enc({})})
    c = _cache(stub)
    c.clear()
    call_names = [name for name, *_ in stub.calls]
    assert "scan_iter" in call_names
    assert "flushdb" not in call_names


def test_clear_redis_error_is_swallowed():
    c = RedisCache(_RaisingRedis())
    c.clear()  # must not raise


# ---------------------------------------------------------------------------
# prefix
# ---------------------------------------------------------------------------


def test_custom_prefix_applied_consistently():
    stub = _StubRedis()
    c = RedisCache(stub, prefix="myservice:rbacx:")
    c.set("k1", {"v": 1}, ttl=10)
    c.get("k1")
    c.delete("k1")
    c.clear()

    for name, *args in stub.calls:
        if name in ("set", "setex", "get", "delete"):
            key = args[0] if name != "delete" else args[0][0]
            assert key.startswith("myservice:rbacx:"), f"{name}: key={key!r}"
        elif name == "scan_iter":
            assert args[0].startswith("myservice:rbacx:")


def test_empty_prefix_works():
    stub = _StubRedis()
    c = RedisCache(stub, prefix="")
    c.set("bare", {"x": 1}, ttl=5)
    assert c.get("bare") == {"x": 1}


# ---------------------------------------------------------------------------
# Integration with Guard
# ---------------------------------------------------------------------------


def test_redis_cache_with_guard():
    """RedisCache integrates correctly with Guard — hit on second call."""
    from rbacx import Action, Context, Guard, Resource, Subject

    stub = _StubRedis()
    cache = RedisCache(stub, prefix="rbacx:", default_ttl=300)

    policy = {
        "algorithm": "deny-overrides",
        "rules": [
            {"id": "r1", "effect": "permit", "actions": ["read"], "resource": {"type": "doc"}},
        ],
    }
    guard = Guard(policy, cache=cache)

    s = Subject(id="u1")
    r = Resource(type="doc", id="1")
    ctx = Context()

    d1 = guard.evaluate_sync(s, Action("read"), r, ctx)
    d2 = guard.evaluate_sync(s, Action("read"), r, ctx)

    assert d1.allowed is True
    assert d2.allowed is True
    # Second call should have hit the Redis cache
    get_calls = [args for name, *args in stub.calls if name == "get"]
    assert len(get_calls) == 2  # both calls check cache


def test_redis_cache_clear_invalidates_guard_cache():
    """After clear(), Guard re-evaluates instead of serving stale results."""
    from rbacx import Action, Context, Guard, Resource, Subject

    stub = _StubRedis()
    cache = RedisCache(stub, prefix="rbacx:", default_ttl=300)
    policy = {
        "algorithm": "deny-overrides",
        "rules": [
            {"id": "r1", "effect": "permit", "actions": ["read"], "resource": {"type": "doc"}},
        ],
    }
    guard = Guard(policy, cache=cache)
    s = Subject(id="u1")
    r = Resource(type="doc", id="1")
    ctx = Context()

    guard.evaluate_sync(s, Action("read"), r, ctx)
    guard.clear_cache()
    guard.evaluate_sync(s, Action("read"), r, ctx)

    # After clear, cache should have been repopulated (two setex calls)
    setex_calls = [args for name, *args in stub.calls if name == "setex"]
    assert len(setex_calls) == 2
