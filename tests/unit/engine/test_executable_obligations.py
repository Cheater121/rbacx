"""Unit tests for executable obligation handlers (Guard.register_obligation_handler)."""

import pytest

from rbacx import Action, Context, Guard, Resource, Subject
from rbacx.core.engine import ObligationNotMetError

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

_POLICY_WITH_MFA = {
    "algorithm": "deny-overrides",
    "rules": [
        {
            "id": "r-permit",
            "effect": "permit",
            "actions": ["read"],
            "resource": {"type": "doc"},
            "obligations": [{"type": "require_mfa", "on": "permit"}],
        }
    ],
}

_POLICY_NO_OBLIGATIONS = {
    "algorithm": "deny-overrides",
    "rules": [
        {"id": "r-permit", "effect": "permit", "actions": ["read"], "resource": {"type": "doc"}},
    ],
}

_POLICY_DENY = {
    "algorithm": "deny-overrides",
    "rules": [
        {"id": "r-deny", "effect": "deny", "actions": ["read"], "resource": {"type": "doc"}},
    ],
}

_POLICY_TWO_OBLIGATIONS = {
    "algorithm": "deny-overrides",
    "rules": [
        {
            "id": "r-permit",
            "effect": "permit",
            "actions": ["read"],
            "resource": {"type": "doc"},
            "obligations": [
                {"type": "require_mfa", "on": "permit"},
                {"type": "require_geo", "on": "permit"},
            ],
        }
    ],
}

_S = Subject(id="u1")
_R = Resource(type="doc", id="d1")
_CTX = Context()


# ---------------------------------------------------------------------------
# No handler registered — backward compatible
# ---------------------------------------------------------------------------


def test_no_handler_registered_permit_unchanged():
    """Without any registered handler permit decisions are unaffected."""
    g = Guard(_POLICY_WITH_MFA)
    d = g.evaluate_sync(_S, Action("read"), _R, _CTX)
    # BasicObligationChecker passes (mfa not in context → denied by checker)
    # but no executable handler is registered so obligations fall through
    assert d.obligations == [{"type": "require_mfa", "on": "permit"}]


def test_no_handler_permit_no_obligations():
    """Rule with no obligations: no handler is ever consulted."""
    g = Guard(_POLICY_NO_OBLIGATIONS)
    d = g.evaluate_sync(_S, Action("read"), _R, _CTX)
    assert d.allowed is True


# ---------------------------------------------------------------------------
# Handler registered — passes (does not raise)
# ---------------------------------------------------------------------------


def test_handler_passes_permit_preserved():
    """Handler that does not raise leaves the decision as permit."""
    g = Guard(_POLICY_WITH_MFA)
    called = []

    def ok_handler(decision, context):
        called.append(True)

    # Bypass BasicObligationChecker by providing mfa=True
    g.register_obligation_handler("require_mfa", ok_handler)
    ctx = Context(attrs={"mfa": True})
    d = g.evaluate_sync(_S, Action("read"), _R, ctx)
    assert d.allowed is True
    assert called == [True]


@pytest.mark.asyncio
async def test_async_handler_passes_permit_preserved():
    """Async handler that does not raise leaves the decision as permit."""
    g = Guard(_POLICY_WITH_MFA)
    called = []

    async def ok_handler(decision, context):
        called.append(True)

    g.register_obligation_handler("require_mfa", ok_handler)
    ctx = Context(attrs={"mfa": True})
    d = await g.evaluate_async(_S, Action("read"), _R, ctx)
    assert d.allowed is True
    assert called == [True]


# ---------------------------------------------------------------------------
# Handler raises ObligationNotMetError
# ---------------------------------------------------------------------------


def test_handler_raises_obligation_not_met_flips_to_deny():
    """ObligationNotMetError from handler flips decision to deny."""
    g = Guard(_POLICY_WITH_MFA)

    def failing_handler(decision, context):
        raise ObligationNotMetError("MFA required")

    g.register_obligation_handler("require_mfa", failing_handler)
    ctx = Context(attrs={"mfa": True})  # bypass BasicObligationChecker
    d = g.evaluate_sync(_S, Action("read"), _R, ctx)
    assert d.allowed is False
    assert d.reason == "obligation_failed"


def test_handler_raises_with_challenge_propagated():
    """challenge from ObligationNotMetError is propagated to Decision."""
    g = Guard(_POLICY_WITH_MFA)

    def failing_handler(decision, context):
        raise ObligationNotMetError("MFA required", challenge="mfa")

    g.register_obligation_handler("require_mfa", failing_handler)
    ctx = Context(attrs={"mfa": True})
    d = g.evaluate_sync(_S, Action("read"), _R, ctx)
    assert d.allowed is False
    assert d.challenge == "mfa"
    assert d.reason == "obligation_failed"


def test_handler_raises_without_challenge_preserves_existing():
    """When ObligationNotMetError has no challenge, existing challenge is kept."""
    g = Guard(_POLICY_WITH_MFA)

    def failing_handler(decision, context):
        raise ObligationNotMetError("failed")  # no challenge

    g.register_obligation_handler("require_mfa", failing_handler)
    ctx = Context(attrs={"mfa": True})
    d = g.evaluate_sync(_S, Action("read"), _R, ctx)
    assert d.allowed is False
    assert d.challenge is None  # no challenge from either checker or handler


@pytest.mark.asyncio
async def test_async_handler_raises_obligation_not_met():
    """Async handler that raises ObligationNotMetError flips to deny."""
    g = Guard(_POLICY_WITH_MFA)

    async def failing_handler(decision, context):
        raise ObligationNotMetError("MFA", challenge="mfa")

    g.register_obligation_handler("require_mfa", failing_handler)
    ctx = Context(attrs={"mfa": True})
    d = await g.evaluate_async(_S, Action("read"), _R, ctx)
    assert d.allowed is False
    assert d.challenge == "mfa"


# ---------------------------------------------------------------------------
# Handler raises unexpected exception — fail-closed
# ---------------------------------------------------------------------------


def test_handler_unexpected_exception_fail_closed():
    """Non-ObligationNotMetError exception is logged and causes deny (fail-closed)."""
    g = Guard(_POLICY_WITH_MFA)

    def broken_handler(decision, context):
        raise RuntimeError("handler crashed")

    g.register_obligation_handler("require_mfa", broken_handler)
    ctx = Context(attrs={"mfa": True})
    d = g.evaluate_sync(_S, Action("read"), _R, ctx)
    assert d.allowed is False
    assert d.reason == "obligation_failed"


# ---------------------------------------------------------------------------
# Deny decisions — handlers never called
# ---------------------------------------------------------------------------


def test_handler_not_called_on_deny():
    """Handlers are only called for permit decisions."""
    g = Guard(_POLICY_DENY)
    called = []

    def handler(decision, context):
        called.append(True)

    g.register_obligation_handler("require_mfa", handler)
    d = g.evaluate_sync(_S, Action("read"), _R, _CTX)
    assert d.allowed is False
    assert called == []


# ---------------------------------------------------------------------------
# Multiple obligations / handlers
# ---------------------------------------------------------------------------


def test_multiple_handlers_all_called():
    """All handlers for obligations present in the decision are called."""
    g = Guard(_POLICY_TWO_OBLIGATIONS)
    called = []

    def mfa_handler(decision, context):
        called.append("mfa")

    def geo_handler(decision, context):
        called.append("geo")

    g.register_obligation_handler("require_mfa", mfa_handler)
    g.register_obligation_handler("require_geo", geo_handler)
    ctx = Context(attrs={"mfa": True})
    d = g.evaluate_sync(_S, Action("read"), _R, ctx)
    assert d.allowed is True
    assert "mfa" in called and "geo" in called


def test_first_handler_fails_second_not_called():
    """When the first handler raises, subsequent handlers are skipped (fail-fast)."""
    g = Guard(_POLICY_TWO_OBLIGATIONS)
    called = []

    def mfa_handler(decision, context):
        called.append("mfa")
        raise ObligationNotMetError("mfa", challenge="mfa")

    def geo_handler(decision, context):
        called.append("geo")

    g.register_obligation_handler("require_mfa", mfa_handler)
    g.register_obligation_handler("require_geo", geo_handler)
    ctx = Context(attrs={"mfa": True})
    d = g.evaluate_sync(_S, Action("read"), _R, ctx)
    assert d.allowed is False
    assert called == ["mfa"]  # geo handler was NOT called


def test_unregistered_obligation_type_ignored():
    """Obligations with no registered handler are left in Decision.obligations."""
    g = Guard(_POLICY_WITH_MFA)
    # Register handler for a DIFFERENT type
    g.register_obligation_handler("require_geo", lambda d, c: None)
    ctx = Context(attrs={"mfa": True})
    d = g.evaluate_sync(_S, Action("read"), _R, ctx)
    # require_mfa has no handler — BasicObligationChecker already passed (mfa=True)
    assert d.allowed is True


# ---------------------------------------------------------------------------
# register_obligation_handler replaces existing
# ---------------------------------------------------------------------------


def test_register_replaces_previous_handler():
    """Registering for an existing type replaces the previous handler."""
    g = Guard(_POLICY_WITH_MFA)
    called = []

    def first(decision, context):
        called.append("first")

    def second(decision, context):
        called.append("second")

    g.register_obligation_handler("require_mfa", first)
    g.register_obligation_handler("require_mfa", second)  # replaces first
    ctx = Context(attrs={"mfa": True})
    g.evaluate_sync(_S, Action("read"), _R, ctx)
    assert called == ["second"]


# ---------------------------------------------------------------------------
# Handler receives correct Decision fields
# ---------------------------------------------------------------------------


def test_handler_receives_decision_with_correct_fields():
    """Handler is called with the fully-built Decision object."""
    g = Guard(_POLICY_WITH_MFA)
    received = {}

    def inspector(decision, context):
        received["allowed"] = decision.allowed
        received["rule_id"] = decision.rule_id
        received["obligations"] = decision.obligations

    g.register_obligation_handler("require_mfa", inspector)
    ctx = Context(attrs={"mfa": True})
    g.evaluate_sync(_S, Action("read"), _R, ctx)
    assert received["allowed"] is True
    assert received["rule_id"] == "r-permit"
    assert any(o.get("type") == "require_mfa" for o in received["obligations"])


# ---------------------------------------------------------------------------
# Cache interaction — handlers still called on cache hit
# ---------------------------------------------------------------------------


def test_handler_called_on_cache_hit():
    """Handlers are executed even when the raw decision is served from cache."""
    from rbacx.core.cache import DefaultInMemoryCache

    g = Guard(_POLICY_WITH_MFA, cache=DefaultInMemoryCache())
    called = []

    def handler(decision, context):
        called.append(True)

    g.register_obligation_handler("require_mfa", handler)
    ctx = Context(attrs={"mfa": True})

    g.evaluate_sync(_S, Action("read"), _R, ctx)  # populates cache
    g.evaluate_sync(_S, Action("read"), _R, ctx)  # cache hit

    assert len(called) == 2


# ---------------------------------------------------------------------------
# Conditional obligation + handler
# ---------------------------------------------------------------------------


def test_handler_respects_conditional_obligation():
    """Handler is only called when the obligation's condition evaluates to True.

    Uses mfa=True in context so BasicObligationChecker passes for both
    resources; the handler is then gated only by the obligation's own condition.
    """
    policy = {
        "algorithm": "deny-overrides",
        "rules": [
            {
                "id": "r1",
                "effect": "permit",
                "actions": ["read"],
                "resource": {"type": "doc"},
                "obligations": [
                    {
                        "type": "require_mfa",
                        "on": "permit",
                        "condition": {"==": [{"attr": "resource.attrs.sensitivity"}, "high"]},
                    }
                ],
            }
        ],
    }
    g = Guard(policy)
    called = []
    # mfa=True so BasicObligationChecker does not block; handler gated by condition
    ctx = Context(attrs={"mfa": True})

    def handler(decision, context):
        called.append(True)

    g.register_obligation_handler("require_mfa", handler)

    # condition False (low) → handler NOT called
    d_low = g.evaluate_sync(
        _S, Action("read"), Resource(type="doc", attrs={"sensitivity": "low"}), ctx
    )
    assert d_low.allowed is True
    assert called == []

    # condition True (high) → handler called
    d_high = g.evaluate_sync(
        _S, Action("read"), Resource(type="doc", attrs={"sensitivity": "high"}), ctx
    )
    assert d_high.allowed is True
    assert called == [True]


# ---------------------------------------------------------------------------
# Batch evaluate
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_handler_called_per_request_in_batch():
    """evaluate_batch_async calls handlers for each request independently."""
    g = Guard(_POLICY_WITH_MFA)
    called = []

    async def handler(decision, context):
        called.append(True)

    g.register_obligation_handler("require_mfa", handler)
    ctx = Context(attrs={"mfa": True})

    results = await g.evaluate_batch_async(
        [
            (_S, Action("read"), _R, ctx),
            (_S, Action("read"), _R, ctx),
            (_S, Action("read"), _R, ctx),
        ]
    )
    assert all(d.allowed for d in results)
    assert len(called) == 3


# ---------------------------------------------------------------------------
# ObligationNotMetError attributes
# ---------------------------------------------------------------------------


def test_obligation_not_met_error_defaults():
    exc = ObligationNotMetError()
    assert exc.challenge is None
    assert str(exc) == ""


def test_obligation_not_met_error_with_challenge():
    exc = ObligationNotMetError("need mfa", challenge="mfa")
    assert exc.challenge == "mfa"
    assert str(exc) == "need mfa"


# ---------------------------------------------------------------------------
# Coverage: condition evaluation errors in handler gating (lines 401-402)
# ---------------------------------------------------------------------------


def test_handler_skipped_on_condition_type_error():
    """When the obligation condition raises ConditionTypeError the handler
    is skipped (fail-safe) and the decision remains permit (lines 401-402)."""
    policy = {
        "algorithm": "deny-overrides",
        "rules": [
            {
                "id": "r1",
                "effect": "permit",
                "actions": ["read"],
                "resource": {"type": "doc"},
                "obligations": [
                    {
                        "type": "require_mfa",
                        "on": "permit",
                        # str > int → ConditionTypeError
                        "condition": {">": [{"attr": "resource.attrs.name"}, 42]},
                    }
                ],
            }
        ],
    }
    g = Guard(policy)
    called = []
    g.register_obligation_handler("require_mfa", lambda d, c: called.append(True))

    d = g.evaluate_sync(
        _S,
        Action("read"),
        Resource(type="doc", attrs={"name": "report"}),
        _CTX,
    )
    assert d.allowed is True
    assert called == []  # handler skipped due to condition error


def test_handler_skipped_on_condition_depth_exceeded():
    """When the obligation condition raises ConditionDepthError the handler
    is skipped (fail-safe) and the decision remains permit (lines 401-402)."""
    from rbacx.core.policy import MAX_CONDITION_DEPTH

    deep: dict = {"==": [1, 1]}
    for _ in range(MAX_CONDITION_DEPTH + 2):
        deep = {"and": [deep]}

    policy = {
        "algorithm": "deny-overrides",
        "rules": [
            {
                "id": "r1",
                "effect": "permit",
                "actions": ["read"],
                "resource": {"type": "doc"},
                "obligations": [{"type": "require_mfa", "on": "permit", "condition": deep}],
            }
        ],
    }
    g = Guard(policy)
    called = []
    g.register_obligation_handler("require_mfa", lambda d, c: called.append(True))

    d = g.evaluate_sync(_S, Action("read"), _R, _CTX)
    assert d.allowed is True
    assert called == []  # handler skipped due to depth error
