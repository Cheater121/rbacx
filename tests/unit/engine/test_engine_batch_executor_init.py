"""
Coverage for engine.py line 431:

    if Guard._executor is None:
        Guard._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="rbacx-sync")

The branch is only reached when evaluate_batch_sync() is called from inside a
running event loop AND Guard._executor is still None at that moment.  Existing
tests may leave _executor already populated, so this test explicitly resets it
to None before the call and restores the original value afterwards.
"""

from concurrent.futures import ThreadPoolExecutor

import pytest

from rbacx.core.engine import Guard
from rbacx.core.model import Action, Context, Resource, Subject

_POLICY = {
    "algorithm": "deny-overrides",
    "rules": [
        {"id": "r1", "effect": "permit", "actions": ["read"], "resource": {"type": "doc"}},
    ],
}
_S = Subject(id="u1")
_R = Resource(type="doc", id="d1")
_CTX = Context()


@pytest.mark.asyncio
async def test_batch_sync_creates_executor_when_none_inside_running_loop():
    """
    evaluate_batch_sync() called from a running loop with _executor=None
    must create a new ThreadPoolExecutor (line 431) and successfully return
    results via it.
    """
    original_executor = Guard._executor
    Guard._executor = None  # force the lazy-init branch
    try:
        g = Guard(_POLICY)

        # We are inside an async test — asyncio.get_running_loop() succeeds,
        # so evaluate_batch_sync takes the ThreadPoolExecutor path.
        results = g.evaluate_batch_sync([(_S, Action("read"), _R, _CTX)])

        # Executor must have been created on line 431
        assert Guard._executor is not None
        assert isinstance(Guard._executor, ThreadPoolExecutor)

        # And the call must have returned a correct result
        assert len(results) == 1
        assert results[0].allowed is True
    finally:
        Guard._executor = original_executor
