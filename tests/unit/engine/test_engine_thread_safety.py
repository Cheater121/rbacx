"""Unit tests for thread-safe Guard.set_policy()."""

import threading
import time
from typing import Any

from rbacx import Action, Context, Guard, Resource, Subject

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

_P_PERMIT: dict[str, Any] = {
    "algorithm": "deny-overrides",
    "rules": [
        {"id": "r-permit", "effect": "permit", "actions": ["read"], "resource": {"type": "doc"}},
    ],
}
_P_DENY: dict[str, Any] = {
    "algorithm": "deny-overrides",
    "rules": [
        {"id": "r-deny", "effect": "deny", "actions": ["read"], "resource": {"type": "doc"}},
    ],
}
_S = Subject(id="u1")
_R = Resource(type="doc", id="d1")
_CTX = Context()


# ---------------------------------------------------------------------------
# Lock presence and type
# ---------------------------------------------------------------------------


def test_policy_lock_exists_and_is_rlock():
    """Guard must expose a _policy_lock that is a reentrant lock."""
    g = Guard(_P_PERMIT)
    assert hasattr(g, "_policy_lock")
    # RLock type varies by platform — check via acquire/release round-trip
    # and that re-acquisition from the same thread does not block.
    acquired = g._policy_lock.acquire(blocking=False)
    assert acquired, "_policy_lock could not be acquired"
    # Re-acquire from same thread — would deadlock with a plain Lock
    re_acquired = g._policy_lock.acquire(blocking=False)
    assert re_acquired, "_policy_lock is not reentrant (plain Lock?)"
    g._policy_lock.release()
    g._policy_lock.release()


# ---------------------------------------------------------------------------
# Re-entrancy: set_policy → _recompute_etag → clear_cache all under same lock
# ---------------------------------------------------------------------------


def test_set_policy_does_not_deadlock():
    """set_policy calls _recompute_etag (and clear_cache) while holding
    _policy_lock.  With a plain non-reentrant Lock this would deadlock.
    With an RLock it must complete immediately."""
    g = Guard(_P_PERMIT)
    # If this returns, re-entrancy works correctly.
    g.set_policy(_P_DENY)
    assert g.evaluate_sync(_S, Action("read"), _R, _CTX).allowed is False


# ---------------------------------------------------------------------------
# Correctness after set_policy
# ---------------------------------------------------------------------------


def test_set_policy_switches_decision():
    """set_policy must atomically replace policy, etag and compiled function."""
    g = Guard(_P_PERMIT)
    assert g.evaluate_sync(_S, Action("read"), _R, _CTX).allowed is True

    g.set_policy(_P_DENY)
    assert g.evaluate_sync(_S, Action("read"), _R, _CTX).allowed is False

    g.set_policy(_P_PERMIT)
    assert g.evaluate_sync(_S, Action("read"), _R, _CTX).allowed is True


def test_etag_changes_on_set_policy():
    """policy_etag must change whenever the policy is replaced."""
    g = Guard(_P_PERMIT)
    etag_before = g.policy_etag
    g.set_policy(_P_DENY)
    assert g.policy_etag != etag_before


def test_compiled_updated_on_set_policy():
    """_compiled must be refreshed after set_policy (not None when compiler
    is available, not the old callable)."""
    g = Guard(_P_PERMIT)
    compiled_before = g._compiled
    g.set_policy(_P_DENY)
    if compiled_before is not None:
        # compiler is available — new compiled must differ from old one
        assert g._compiled is not None
        assert g._compiled is not compiled_before


def test_update_policy_alias():
    """update_policy() is a backward-compatible alias for set_policy()."""
    g = Guard(_P_PERMIT)
    g.update_policy(_P_DENY)
    assert g.evaluate_sync(_S, Action("read"), _R, _CTX).allowed is False


# ---------------------------------------------------------------------------
# Thread-safety: concurrent set_policy + evaluate_sync must not crash
# ---------------------------------------------------------------------------


def test_concurrent_set_policy_no_exception():
    """Writer thread rapidly alternates between two policies while reader
    threads continuously evaluate.  No exception must be raised and every
    result must be a valid boolean (True or False)."""
    g = Guard(_P_PERMIT)
    errors: list[str] = []
    results: list[bool] = []
    stop = threading.Event()

    def writer() -> None:
        for _ in range(60):
            g.set_policy(_P_DENY)
            time.sleep(0.001)
            g.set_policy(_P_PERMIT)
        stop.set()

    def reader() -> None:
        while not stop.is_set():
            try:
                d = g.evaluate_sync(_S, Action("read"), _R, _CTX)
                results.append(d.allowed)
            except Exception as exc:
                errors.append(str(exc))

    threads = [threading.Thread(target=writer)]
    threads += [threading.Thread(target=reader) for _ in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    assert not errors, f"Exceptions during concurrent access: {errors}"
    assert results, "No results collected — readers may not have run"
    assert all(isinstance(r, bool) for r in results)


def test_concurrent_set_policy_etag_never_stale():
    """After each set_policy call, policy_etag must correspond to the
    current policy — never to the previous one.

    Verifies that the (policy, etag, _compiled) triple is updated atomically
    from the perspective of the writing thread.
    """
    import hashlib
    import json

    g = Guard(_P_PERMIT)
    mismatches: list[str] = []

    def writer() -> None:
        for i in range(40):
            p = _P_DENY if i % 2 else _P_PERMIT
            g.set_policy(p)
            # Immediately after set_policy, etag must match current policy
            expected = hashlib.sha3_256(json.dumps(p, sort_keys=True).encode()).hexdigest()
            if g.policy_etag != expected:
                mismatches.append(f"iteration {i}: etag={g.policy_etag!r} expected={expected!r}")

    threads = [threading.Thread(target=writer) for _ in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    assert not mismatches, "Stale etag detected:\n" + "\n".join(mismatches)
