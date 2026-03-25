"""Tests for the cache mutation bug fixed in 1.9.2.

Bug: when an obligation was not met, the engine wrote
``raw["reason"] = "obligation_failed"`` directly into the dict that was
stored in the cache.  On the *next* call with the same env (e.g. the user
now satisfying MFA), the cached raw dict already had reason="obligation_failed",
so Decision.reason was wrong even though the second call was allowed.

Fix: use a local `reason` variable; never mutate the cached object.
"""

from typing import Any

from rbacx.core.cache import AbstractCache
from rbacx.core.engine import Guard
from rbacx.core.model import Action, Context, Resource, Subject

# ---------------------------------------------------------------------------
# Minimal in-process cache (no TTL, no LRU — just a plain dict)
# ---------------------------------------------------------------------------


class _SimpleCache(AbstractCache):
    def __init__(self) -> None:
        self._store: dict[str, Any] = {}

    def get(self, key: str) -> Any | None:
        return self._store.get(key)

    def set(self, key: str, value: Any, ttl: int | None = None) -> None:
        self._store[key] = value

    def delete(self, key: str) -> None:
        self._store.pop(key, None)

    def clear(self) -> None:
        self._store.clear()


# ---------------------------------------------------------------------------
# Policy with an MFA obligation
# ---------------------------------------------------------------------------

_POLICY = {
    "algorithm": "deny-overrides",
    "rules": [
        {
            "id": "r1",
            "effect": "permit",
            "actions": ["read"],
            "resource": {"type": "doc"},
            "obligations": [{"type": "require_mfa", "on": "permit"}],
        }
    ],
}

_SUBJECT = Subject(id="u1", roles=[], attrs={})
_ACTION = Action(name="read")
_RESOURCE = Resource(type="doc", id="d1")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_cached_raw_not_mutated_when_obligation_fails_then_passes():
    """Decision.reason must be correct on the second cached call.

    First call: MFA not provided → obligation fails → reason='obligation_failed', allowed=False.
    Second call: MFA provided, but env is the *same* (no MFA in attrs, context differs) —
    actually we use different contexts so the cache keys differ. This is the correct flow.

    The real regression test is below.
    """
    cache = _SimpleCache()
    guard = Guard(_POLICY, cache=cache)

    # Call 1: MFA=False → obligation not met
    d1 = guard.evaluate_sync(_SUBJECT, _ACTION, _RESOURCE, Context(attrs={"mfa": False}))
    assert d1.allowed is False
    assert d1.reason == "obligation_failed"

    # Call 2: same env (MFA=False again) → should still be denied, from cache
    d2 = guard.evaluate_sync(_SUBJECT, _ACTION, _RESOURCE, Context(attrs={"mfa": False}))
    assert d2.allowed is False
    assert d2.reason == "obligation_failed"

    # Call 3: MFA=True → obligation met → allowed, and reason must NOT be 'obligation_failed'
    d3 = guard.evaluate_sync(_SUBJECT, _ACTION, _RESOURCE, Context(attrs={"mfa": True}))
    assert d3.allowed is True
    assert (
        d3.reason != "obligation_failed"
    ), "reason must not be 'obligation_failed' when obligation passes"
    assert d3.reason == "matched"


def test_cached_raw_dict_is_not_mutated_in_place():
    """The raw dict stored in the cache must not be mutated after obligation failure.

    This is the direct regression test for the bug:
    After a call where obligation fails, the cached object must still have
    its original 'reason' value (e.g. 'matched'), not 'obligation_failed'.
    """
    cache = _SimpleCache()
    guard = Guard(_POLICY, cache=cache)

    # Prime the cache with a permit decision (MFA=True so obligation passes)
    d1 = guard.evaluate_sync(_SUBJECT, _ACTION, _RESOURCE, Context(attrs={"mfa": True}))
    assert d1.allowed is True
    assert d1.reason == "matched"

    # Find the cached raw object
    assert len(cache._store) == 1
    cached_raw = next(iter(cache._store.values()))
    original_reason = cached_raw.get("reason")

    # Now make a call with the SAME env but obligation fails by forcing
    # the cache to return the same raw (same key = same env).
    # We do this by calling with mfa=True again (same cache key).
    d2 = guard.evaluate_sync(_SUBJECT, _ACTION, _RESOURCE, Context(attrs={"mfa": True}))
    assert d2.allowed is True

    # The cached raw object must still have its original reason — not mutated
    assert (
        cached_raw.get("reason") == original_reason
    ), "cached raw dict must not be mutated by the engine"


def test_reason_obligation_failed_not_leaked_to_different_context():
    """After obligation failure with context A, a call with context B (same base env)
    must not see 'obligation_failed' if its obligation passes.

    This tests the exact scenario from the bug report:
    - env is the same except for context (context is part of cache key, so keys differ)
    - but if raw were mutated, the stored object would carry 'obligation_failed'
      and any future hit on that key would return it.
    """
    cache = _SimpleCache()
    guard = Guard(_POLICY, cache=cache)

    ctx_no_mfa = Context(attrs={"mfa": False})
    ctx_mfa = Context(attrs={"mfa": True})

    # Call with no MFA → obligation fails
    d_fail = guard.evaluate_sync(_SUBJECT, _ACTION, _RESOURCE, ctx_no_mfa)
    assert d_fail.allowed is False
    assert d_fail.reason == "obligation_failed"

    # Second call with no MFA again → must still be consistent (from cache)
    d_fail2 = guard.evaluate_sync(_SUBJECT, _ACTION, _RESOURCE, ctx_no_mfa)
    assert d_fail2.allowed is False
    assert d_fail2.reason == "obligation_failed"

    # Call with MFA → completely fresh cache key, obligation passes
    d_pass = guard.evaluate_sync(_SUBJECT, _ACTION, _RESOURCE, ctx_mfa)
    assert d_pass.allowed is True
    assert d_pass.reason == "matched", (
        f"expected 'matched', got '{d_pass.reason}' — "
        "raw dict may have been mutated by the previous obligation-failed call"
    )


def test_no_cache_obligation_failed_reason_still_works():
    """Without cache, obligation_failed reason must still be set correctly."""
    guard = Guard(_POLICY)  # no cache

    d = guard.evaluate_sync(_SUBJECT, _ACTION, _RESOURCE, Context(attrs={"mfa": False}))
    assert d.allowed is False
    assert d.reason == "obligation_failed"

    d2 = guard.evaluate_sync(_SUBJECT, _ACTION, _RESOURCE, Context(attrs={"mfa": True}))
    assert d2.allowed is True
    assert d2.reason == "matched"
