import typing as _t

from rbacx.core.cache import AbstractCache
from rbacx.core.engine import Guard
from rbacx.core.model import Action, Context, Resource, Subject
from rbacx.core.ports import DecisionLogSink

# ---------- test doubles ----------


class _LogSink(DecisionLogSink):
    """Sync logger sink to capture payloads passed by engine."""

    def __init__(self) -> None:
        self.payloads: list[dict] = []

    def log(self, payload: dict) -> None:  # sync variant is allowed by engine
        self.payloads.append(payload)


class _MemCache(AbstractCache):
    """Simple in-memory cache to observe get/set calls and key cardinality."""

    def __init__(self) -> None:
        self.store: dict[str, _t.Any] = {}
        self.get_count = 0
        self.set_count = 0
        self.clear_count = 0

    def get(self, key: str):
        self.get_count += 1
        return self.store.get(key)

    def set(self, key: str, value, ttl: int | None = None):
        self.set_count += 1
        self.store[key] = value

    def clear(self):
        self.clear_count += 1
        self.store.clear()


# ---------- fixtures/helpers ----------


def _permit_policy() -> dict:
    # Minimal policy that always permits for action "read" and resource type "doc"
    return {
        "algorithm": "deny-overrides",
        "rules": [
            {
                "id": "r1",
                "actions": ["read"],
                "resource": {"type": "doc"},
                "effect": "permit",
            }
        ],
    }


def _ctx():
    return (
        Subject(id="u1", roles=["user"], attrs={"lvl": 1}),
        Action(name="read"),
        Resource(type="doc", id="d1", attrs={"tag": "x"}),
        Context(attrs={"ip": "127.0.0.1"}),
    )


# ---------- tests ----------


def test_env_has_no_strict_flag_when_disabled():
    logger = _LogSink()
    guard = Guard(_permit_policy(), logger_sink=logger, strict_types=False)

    subj, act, res, ctx = _ctx()
    d = guard.evaluate_sync(subj, act, res, ctx)
    assert d.allowed is True

    # Last logged payload contains the env we want to inspect
    assert logger.payloads, "decision logger did not receive a payload"
    env = logger.payloads[-1]["env"]
    assert (
        "__strict_types__" not in env
    ), "flag must be absent in lax mode to keep cache keys stable"


def test_env_has_strict_flag_when_enabled():
    logger = _LogSink()
    guard = Guard(_permit_policy(), logger_sink=logger, strict_types=True)

    subj, act, res, ctx = _ctx()
    d = guard.evaluate_sync(subj, act, res, ctx)
    assert d.allowed is True

    env = logger.payloads[-1]["env"]
    assert env.get("__strict_types__") is True, "flag must be present and True in strict mode"


def test_cache_hit_in_lax_mode_and_separation_for_strict_mode():
    cache = _MemCache()

    # 1) Lax guard — two evaluations should hit cache on the second call
    guard_lax = Guard(_permit_policy(), cache=cache, strict_types=False)
    subj, act, res, ctx = _ctx()

    d1 = guard_lax.evaluate_sync(subj, act, res, ctx)
    d2 = guard_lax.evaluate_sync(subj, act, res, ctx)
    assert d1.allowed is True and d2.allowed is True
    # exactly one set (first call), second call is a hit
    assert cache.set_count == 1, "lax mode must not alter cache key; second call should be a hit"

    # 2) Strict guard with the same cache — should generate a different key → another set
    guard_strict = Guard(_permit_policy(), cache=cache, strict_types=True)
    d3 = guard_strict.evaluate_sync(subj, act, res, ctx)
    assert d3.allowed is True

    # A second distinct entry should be stored for strict mode
    assert cache.set_count == 2, "strict mode must use a distinct cache key from lax mode"
    assert len(cache.store) == 2, "cache should contain separate entries for lax and strict modes"
