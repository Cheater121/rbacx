# -*- coding: utf-8 -*-
import types

import pytest

import rbacx.core.engine as eng
from rbacx.core.engine import Guard
from rbacx.core.model import Action, Context, Resource, Subject


# ---------- 117: policyset branch in _decide_async (return await asyncio.to_thread(decide_policyset, ...)) ----------
@pytest.mark.asyncio
async def test__decide_async_policyset_branch(monkeypatch):
    # Force the policyset branch by disabling compilation entirely,
    # so _decide_async cannot return via the compiled function path.
    monkeypatch.setattr(eng, "compile_policy", None, raising=True)

    called = {}

    # Patch decide_policyset so we can ensure that branch is taken.
    def fake_decide_policyset(policyset, env):
        called["policyset"] = True
        # minimal decision shape
        return {"decision": "deny", "reason": "no_match"}

    monkeypatch.setattr(eng, "decide_policyset", fake_decide_policyset, raising=True)

    # Presence of "policies" triggers policyset path when no compiled fn is set.
    g = Guard(policy={"policies": []})
    # Double-ensure compiled is not set in case of prior state.
    g._compiled = None  # noqa: SLF001  # test-only: ensure compiled path is impossible

    out = await g._decide_async({"env": True})

    # Must have gone through decide_policyset branch
    assert called.get("policyset") is True
    assert out["decision"] == "deny"
    assert out["reason"] == "no_match"


# ---------- 101: update_policy is an alias to set_policy ----------
def test_update_policy_calls_set_policy_alias(monkeypatch):
    g = Guard(policy={"rules": []})
    called = {}

    # Replace bound method to observe the call; keep signature (self, policy)
    def fake_set_policy(self, policy):
        called["policy"] = policy

    monkeypatch.setattr(
        g,
        "set_policy",
        types.MethodType(fake_set_policy, g),
        raising=False,
    )

    new_policy = {"rules": [{"id": "r1", "actions": ["*"], "resource": {}, "effect": "permit"}]}
    g.update_policy(new_policy)

    assert called.get("policy") == new_policy


# ---------- 187–194: metrics.inc branch when inc is ABSENT (inc is None) ----------
@pytest.mark.asyncio
async def test_metrics_inc_absent_branch_skips_without_error():
    # Metrics object without 'inc' attribute to hit: inc = getattr(..., "inc", None) -> None,
    # and take the "if inc is not None" == False path.
    class MetricsNoInc:
        # Keep observe present but harmless to avoid affecting the test path
        def observe(self, name, value, labels):
            pass

    policy = {"rules": [{"id": "ok", "actions": ["*"], "resource": {}, "effect": "permit"}]}
    g = Guard(policy=policy, metrics=MetricsNoInc())

    d = await g.evaluate_async(
        Subject(id="u", roles=[], attrs={}),
        Action(name="read"),
        Resource(type="doc", id="1", attrs={}),
        Context(attrs={}),
    )
    # Decision remains permit; most importantly, the branch with inc==None is executed without exceptions.
    assert d.allowed is True


# ---------- 187–194: metrics.inc async branch ----------
@pytest.mark.asyncio
async def test_metrics_inc_async_branch_called():
    calls = {}

    class MetricsAsyncInc:
        # Async inc should take the "await inc(...)" path
        async def inc(self, name, labels):
            calls["inc"] = (name, dict(labels))

    policy = {"rules": [{"id": "ok", "actions": ["*"], "resource": {}, "effect": "permit"}]}
    g = Guard(policy=policy, metrics=MetricsAsyncInc())

    _ = await g.evaluate_async(
        Subject(id="u", roles=[], attrs={}),
        Action(name="read"),
        Resource(type="doc", id="1", attrs={}),
        Context(attrs={}),
    )

    assert calls.get("inc") is not None
    name, labels = calls["inc"]
    assert name == "rbacx_decisions_total"
    assert labels.get("decision") == "permit"


# ---------- 187–194: metrics.inc exception branch (catch path) ----------
@pytest.mark.asyncio
async def test_metrics_inc_exception_branch_is_caught():
    # Raise from inc to exercise the try/except arc for metrics.inc
    class MetricsRaiseInc:
        def inc(self, name, labels):
            raise RuntimeError("boom-inc")

        # Keep observe as a harmless sync method to avoid extra noise
        def observe(self, name, value, labels):
            return None

    policy = {"rules": [{"id": "ok", "actions": ["*"], "resource": {}, "effect": "permit"}]}
    g = Guard(policy=policy, metrics=MetricsRaiseInc())

    # Should not raise; exception must be swallowed by the engine
    d = await g.evaluate_async(
        Subject(id="u", roles=[], attrs={}),
        Action(name="read"),
        Resource(type="doc", id="1", attrs={}),
        Context(attrs={}),
    )
    assert d.allowed is True  # decision still permit


# ---------- 279–280: is_allowed_async returns d.allowed ----------
@pytest.mark.asyncio
async def test_is_allowed_async_returns_bool():
    policy = {"rules": [{"id": "ok", "actions": ["*"], "resource": {}, "effect": "permit"}]}
    g = Guard(policy=policy)

    allowed = await g.is_allowed_async(
        Subject(id="u", roles=[], attrs={}),
        Action(name="read"),
        Resource(type="doc", id="1", attrs={}),
        Context(attrs={}),
    )

    assert allowed is True


# ---------- 209–225: logger_sink.log sync branch ----------
@pytest.mark.asyncio
async def test_logger_sink_log_sync_branch_called():
    # Sync log should take the "else: log(payload)" path
    received = {}

    class LoggerSync:
        def log(self, payload):
            received.update(payload)

    policy = {"rules": [{"id": "ok", "actions": ["*"], "resource": {}, "effect": "permit"}]}
    g = Guard(policy=policy, logger_sink=LoggerSync())

    d = await g.evaluate_async(
        Subject(id="u", roles=[], attrs={}),
        Action(name="read"),
        Resource(type="doc", id="1", attrs={}),
        Context(attrs={}),
    )

    # Ensure the sink was called and payload matches decision fields
    assert received.get("decision") == d.effect
    assert received.get("allowed") == d.allowed
    assert "env" in received
    assert "rule_id" in received and "policy_id" in received and "reason" in received


# ---------- 209–225: logger_sink.log async branch ----------
@pytest.mark.asyncio
async def test_logger_sink_log_async_branch_called():
    # Async log should take the "await log(payload)" path
    received = {}

    class LoggerAsync:
        async def log(self, payload):
            received.update(payload)

    policy = {"rules": [{"id": "ok", "actions": ["*"], "resource": {}, "effect": "permit"}]}
    g = Guard(policy=policy, logger_sink=LoggerAsync())

    d = await g.evaluate_async(
        Subject(id="u", roles=[], attrs={}),
        Action(name="read"),
        Resource(type="doc", id="1", attrs={}),
        Context(attrs={}),
    )

    assert received.get("decision") == d.effect
    assert received.get("allowed") == d.allowed
    assert "env" in received


# ---------- 209–225: logger_sink.log is ABSENT (log is None) ----------
@pytest.mark.asyncio
async def test_logger_sink_no_log_method_skips_without_error():
    class LoggerNoLog:
        pass

    policy = {"rules": [{"id": "ok", "actions": ["*"], "resource": {}, "effect": "permit"}]}
    g = Guard(policy=policy, logger_sink=LoggerNoLog())

    d = await g.evaluate_async(
        Subject(id="u", roles=[], attrs={}),
        Action(name="read"),
        Resource(type="doc", id="1", attrs={}),
        Context(attrs={}),
    )
    assert d.allowed is True  # path where `log is None` executed


# ---------- 209–225: logger_sink.log SYNC branch ----------
@pytest.mark.asyncio
async def test_logger_sink_log_sync_branch_covers_else_path():
    received = {}

    class LoggerSync:
        def log(self, payload):
            received.update(payload)  # covers `else: log(payload)`

    policy = {"rules": [{"id": "ok", "actions": ["*"], "resource": {}, "effect": "permit"}]}
    g = Guard(policy=policy, logger_sink=LoggerSync())

    d = await g.evaluate_async(
        Subject(id="u", roles=[], attrs={}),
        Action(name="read"),
        Resource(type="doc", id="1", attrs={}),
        Context(attrs={}),
    )

    assert received.get("decision") == d.effect
    assert received.get("allowed") == d.allowed
    assert "env" in received and "reason" in received


# ---------- 209–225: logger_sink.log ASYNC branch ----------
@pytest.mark.asyncio
async def test_logger_sink_log_async_branch_covers_await_path():
    received = {}

    class LoggerAsync:
        async def log(self, payload):
            received.update(payload)  # covers `await log(payload)`

    policy = {"rules": [{"id": "ok", "actions": ["*"], "resource": {}, "effect": "permit"}]}
    g = Guard(policy=policy, logger_sink=LoggerAsync())

    d = await g.evaluate_async(
        Subject(id="u", roles=[], attrs={}),
        Action(name="read"),
        Resource(type="doc", id="1", attrs={}),
        Context(attrs={}),
    )

    assert received.get("decision") == d.effect
    assert received.get("allowed") == d.allowed
    assert "env" in received and "reason" in received
