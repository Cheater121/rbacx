import asyncio
import threading
import time

import pytest

import rbacx.core.engine as engine_mod
from rbacx.core.engine import Guard
from rbacx.core.model import Action, Context, Resource, Subject

# ---------------------------- helpers (DI doubles) -----------------------------


class AsyncRoleResolver:
    def __init__(self):
        self.calls = 0

    async def expand(self, roles):
        self.calls += 1
        await asyncio.sleep(0)  # yield control
        return list(roles) + ["extra"]


class FailingRoleResolver:
    def expand(self, roles):
        raise RuntimeError("boom")


class AsyncObligationChecker:
    def __init__(self, ok=True, challenge=None):
        self.calls = 0
        self.ok = ok
        self.challenge = challenge

    async def check(self, raw, ctx):
        self.calls += 1
        await asyncio.sleep(0)
        return self.ok, self.challenge


class SyncObligationChecker:
    def __init__(self, ok=True, challenge=None):
        self.calls = 0
        self.ok = ok
        self.challenge = challenge

    def check(self, raw, ctx):
        self.calls += 1  # sync path
        return self.ok, self.challenge


class AsyncMetrics:
    def __init__(self):
        self.inc_calls = []
        self.observe_calls = []

    async def inc(self, name, labels):
        self.inc_calls.append((name, labels))
        await asyncio.sleep(0)

    async def observe(self, name, value, labels):
        self.observe_calls.append((name, value, labels))
        await asyncio.sleep(0)


class SyncMetrics:
    def __init__(self):
        self.inc_calls = []
        self.observe_calls = []

    def inc(self, name, labels):
        self.inc_calls.append((name, labels))

    def observe(self, name, value, labels):
        self.observe_calls.append((name, value, labels))


class AsyncLoggerSink:
    def __init__(self):
        self.payloads = []

    async def log(self, payload):
        self.payloads.append(payload)
        await asyncio.sleep(0)


class SyncLoggerSink:
    def __init__(self):
        self.payloads = []

    def log(self, payload):
        self.payloads.append(payload)


# ---------------------------- stubs for decision core --------------------------


def _permit_raw(rule_id="r1"):
    # minimal shape used by engine
    return {"decision": "permit", "rule_id": rule_id}


async def _stub_decide_async_permit(self, env):
    # Used to bypass real policy logic; keeps tests stable
    await asyncio.sleep(0)
    return _permit_raw("stub")


# ------------------------------------ tests ------------------------------------


@pytest.mark.asyncio
async def test_async_path_with_async_injections_and_permit(monkeypatch):
    """
    evaluate_async:
      - uses async resolver/obligations/metrics/logger via await
      - returns permit, metrics and logger called
    """
    # Monkeypatch the engine's async decision to a deterministic stub
    monkeypatch.setattr(Guard, "_decide_async", _stub_decide_async_permit, raising=True)

    metrics = AsyncMetrics()
    sink = AsyncLoggerSink()
    resolver = AsyncRoleResolver()
    obligations = AsyncObligationChecker(ok=True, challenge=None)

    g = Guard(
        policy={"any": "thing"},
        logger_sink=sink,
        metrics=metrics,
        obligation_checker=obligations,
        role_resolver=resolver,
    )

    sub = Subject(id="u", roles=["r"])
    act = Action(name="read")
    res = Resource(type="doc", id="1")
    ctx = Context()

    d = await g.evaluate_async(sub, act, res, ctx)

    assert d.allowed is True and d.effect == "permit"
    # metrics called
    assert metrics.inc_calls and metrics.observe_calls
    # logger called
    assert sink.payloads and sink.payloads[-1]["decision"] == "permit"
    # resolver used once
    assert resolver.calls == 1
    # obligations checked once
    assert obligations.calls == 1


@pytest.mark.asyncio
async def test_evaluate_sync_inside_running_loop_works():
    """
    Calling sync API while a loop is running should still work
    (engine runs async core in a helper thread).
    """
    # Use a real permit policy (no monkeypatch needed)
    policy = {
        "algorithm": "deny-overrides",
        "rules": [
            {"id": "r", "effect": "permit", "actions": ["read"], "resource": {"type": "doc"}}
        ],
    }

    g = Guard(policy)

    sub = Subject(id="u", roles=["r"])
    act = Action(name="read")
    res = Resource(type="doc", id="1")
    ctx = Context()

    # This call happens while an event loop is active (we are in @pytest.mark.asyncio)
    d = g.evaluate_sync(sub, act, res, ctx)
    assert d.allowed is True and d.effect == "permit"


@pytest.mark.asyncio
async def test_policy_decider_runs_in_worker_thread(monkeypatch):
    """
    When evaluate_async is used, CPU-bound policy evaluation runs via asyncio.to_thread
    (i.e., not on the main event loop thread).
    """
    called = {}

    def stub_decide_policy(policy, env):
        called["thread"] = threading.current_thread().name
        # emulate some CPU / blocking work
        time.sleep(0.02)
        return {"decision": "permit", "rule_id": "decide_policy_stub"}

    # Patch the exact symbol used by Guard (_decide_async calls engine_mod.decide_policy)
    monkeypatch.setattr(engine_mod, "decide_policy", stub_decide_policy, raising=True)

    # Simple policy (not policyset), and disable any compiled function just in case
    policy = {
        "rules": [{"id": "r", "effect": "permit", "actions": ["read"], "resource": {"type": "doc"}}]
    }
    g = Guard(policy)
    # Ensure compiled fast-path is not used
    if hasattr(g, "_compiled"):
        g._compiled = None  # type: ignore[attr-defined]

    sub = Subject(id="u", roles=["r"])
    act = Action(name="read")
    res = Resource(type="doc", id="1")
    ctx = Context()

    main_thread = threading.current_thread().name
    d = await g.evaluate_async(sub, act, res, ctx)

    assert d.allowed is True
    # verify stub executed in a different thread (asyncio.to_thread)
    assert "thread" in called and called["thread"] != main_thread


def test_obligations_auto_deny_and_reason(monkeypatch):
    """
    If obligations are not met, engine auto-denies with reason 'obligation_failed'
    and propagates challenge.
    """

    async def decide_permit(self, env):
        return _permit_raw("permit_before_obligation")

    monkeypatch.setattr(Guard, "_decide_async", decide_permit, raising=True)

    # sync metrics/logger to keep this a pure sync test
    metrics = SyncMetrics()
    sink = SyncLoggerSink()
    obligations = SyncObligationChecker(ok=False, challenge="mfa_required")

    g = Guard(policy={"p": 1}, logger_sink=sink, metrics=metrics, obligation_checker=obligations)

    sub = Subject(id="u", roles=["r"])
    act = Action(name="read")
    res = Resource(type="doc", id="1")
    ctx = Context()

    d = g.evaluate_sync(sub, act, res, ctx)

    assert d.allowed is False
    assert d.effect == "deny"
    assert d.reason == "obligation_failed"
    assert d.challenge == "mfa_required"
    # metrics & logger were called even on deny
    assert metrics.inc_calls and metrics.observe_calls
    assert sink.payloads and sink.payloads[-1]["decision"] == "deny"


@pytest.mark.asyncio
async def test_resolver_exception_is_swallowed(monkeypatch):
    """
    Exceptions in role resolver must not crash evaluation.
    """
    monkeypatch.setattr(Guard, "_decide_async", _stub_decide_async_permit, raising=True)

    g = Guard(policy={"p": 1}, role_resolver=FailingRoleResolver())

    sub = Subject(id="u", roles=["r"])
    act = Action(name="read")
    res = Resource(type="doc", id="1")
    ctx = Context()

    d = await g.evaluate_async(sub, act, res, ctx)
    assert d.allowed is True and d.effect == "permit"
