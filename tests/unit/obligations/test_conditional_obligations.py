"""Unit tests for conditional obligations (``condition`` field on obligation objects)."""

import pytest

from rbacx import Action, Context, Guard, Resource, Subject
from rbacx.core.cache import DefaultInMemoryCache

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_S = Subject(id="u1")
_CTX = Context()


def _guard(obligations: list, *, resource_type: str = "doc") -> Guard:
    """Build a Guard with a single permit rule carrying the given obligations."""
    return Guard(
        {
            "rules": [
                {
                    "id": "r1",
                    "effect": "permit",
                    "actions": ["read"],
                    "resource": {"type": resource_type},
                    "obligations": obligations,
                }
            ]
        }
    )


def _resource(**attrs) -> Resource:
    return Resource(type="doc", id="d1", attrs=attrs)


# ---------------------------------------------------------------------------
# Backward compatibility — obligation without condition
# ---------------------------------------------------------------------------


def test_no_condition_mfa_required_and_met():
    """Obligation without condition: MFA required and provided → permit."""
    g = _guard([{"type": "require_mfa", "on": "permit"}])
    d = g.evaluate_sync(_S, Action("read"), _resource(), Context(attrs={"mfa": True}))
    assert d.allowed is True


def test_no_condition_mfa_required_not_met():
    """Obligation without condition: MFA required but missing → deny."""
    g = _guard([{"type": "require_mfa", "on": "permit"}])
    d = g.evaluate_sync(_S, Action("read"), _resource(), Context(attrs={"mfa": False}))
    assert d.allowed is False
    assert d.reason == "obligation_failed"


# ---------------------------------------------------------------------------
# condition evaluates to True → obligation IS enforced
# ---------------------------------------------------------------------------


def test_condition_true_obligation_enforced():
    """condition=True: obligation fires, MFA not provided → deny."""
    g = _guard(
        [
            {
                "type": "require_mfa",
                "on": "permit",
                "condition": {"==": [{"attr": "resource.attrs.sensitivity"}, "high"]},
            }
        ]
    )
    d = g.evaluate_sync(
        _S,
        Action("read"),
        _resource(sensitivity="high"),
        Context(attrs={"mfa": False}),
    )
    assert d.allowed is False
    assert d.reason == "obligation_failed"


def test_condition_true_obligation_met_permit():
    """condition=True: obligation fires, MFA provided → permit."""
    g = _guard(
        [
            {
                "type": "require_mfa",
                "on": "permit",
                "condition": {"==": [{"attr": "resource.attrs.sensitivity"}, "high"]},
            }
        ]
    )
    d = g.evaluate_sync(
        _S,
        Action("read"),
        _resource(sensitivity="high"),
        Context(attrs={"mfa": True}),
    )
    assert d.allowed is True


# ---------------------------------------------------------------------------
# condition evaluates to False → obligation is SKIPPED
# ---------------------------------------------------------------------------


def test_condition_false_obligation_skipped():
    """condition=False: obligation not enforced even if MFA absent → permit."""
    g = _guard(
        [
            {
                "type": "require_mfa",
                "on": "permit",
                "condition": {"==": [{"attr": "resource.attrs.sensitivity"}, "high"]},
            }
        ]
    )
    d = g.evaluate_sync(
        _S,
        Action("read"),
        _resource(sensitivity="low"),
        Context(attrs={"mfa": False}),
    )
    assert d.allowed is True


# ---------------------------------------------------------------------------
# condition referencing different env namespaces
# ---------------------------------------------------------------------------


def test_condition_on_resource_attr():
    """condition can reference resource.attrs.*."""
    g = _guard(
        [
            {
                "type": "require_mfa",
                "on": "permit",
                "condition": {"==": [{"attr": "resource.attrs.sensitivity"}, "high"]},
            }
        ]
    )
    assert (
        g.evaluate_sync(
            _S, Action("read"), _resource(sensitivity="high"), Context(attrs={"mfa": False})
        ).allowed
        is False
    )
    assert (
        g.evaluate_sync(
            _S, Action("read"), _resource(sensitivity="low"), Context(attrs={"mfa": False})
        ).allowed
        is True
    )


def test_condition_on_subject_attr():
    """condition can reference subject.attrs.*."""
    g = _guard(
        [
            {
                "type": "require_mfa",
                "on": "permit",
                "condition": {"==": [{"attr": "subject.attrs.tier"}, "premium"]},
            }
        ]
    )
    s_premium = Subject(id="u", attrs={"tier": "premium"})
    s_free = Subject(id="u", attrs={"tier": "free"})
    assert (
        g.evaluate_sync(
            s_premium, Action("read"), _resource(), Context(attrs={"mfa": False})
        ).allowed
        is False
    )
    assert (
        g.evaluate_sync(s_free, Action("read"), _resource(), Context(attrs={"mfa": False})).allowed
        is True
    )


def test_condition_on_context_attr():
    """condition can reference context.* attributes."""
    g = _guard(
        [
            {
                "type": "require_mfa",
                "on": "permit",
                "condition": {"==": [{"attr": "context.country"}, "RU"]},
            }
        ]
    )
    assert (
        g.evaluate_sync(
            _S, Action("read"), _resource(), Context(attrs={"country": "RU", "mfa": False})
        ).allowed
        is False
    )
    assert (
        g.evaluate_sync(
            _S, Action("read"), _resource(), Context(attrs={"country": "US", "mfa": False})
        ).allowed
        is True
    )


# ---------------------------------------------------------------------------
# Fail-safe: broken conditions skip the obligation
# ---------------------------------------------------------------------------


def test_condition_type_error_skips_obligation():
    """ConditionTypeError in obligation condition → obligation skipped (fail-safe)."""
    g = _guard(
        [
            {
                "type": "require_mfa",
                "on": "permit",
                "condition": {">": [{"attr": "subject.id"}, 42]},  # str > int → type error
            }
        ]
    )
    d = g.evaluate_sync(_S, Action("read"), _resource(), Context(attrs={"mfa": False}))
    assert d.allowed is True  # obligation skipped, permit stands


def test_condition_depth_exceeded_skips_obligation():
    """ConditionDepthError in obligation condition → obligation skipped (fail-safe)."""
    from rbacx.core.policy import MAX_CONDITION_DEPTH

    deep: dict = {"==": [1, 1]}
    for _ in range(MAX_CONDITION_DEPTH + 2):
        deep = {"and": [deep]}
    g = _guard(
        [
            {
                "type": "require_mfa",
                "on": "permit",
                "condition": deep,
            }
        ]
    )
    d = g.evaluate_sync(_S, Action("read"), _resource(), Context(attrs={"mfa": False}))
    assert d.allowed is True  # obligation skipped, permit stands


# ---------------------------------------------------------------------------
# Multiple obligations — selective enforcement via condition
# ---------------------------------------------------------------------------


def test_multiple_obligations_only_matching_condition_enforced():
    """When obligations mix conditional and unconditional, only applicable ones fire."""
    g = _guard(
        [
            # always required
            {"type": "require_terms_accept", "on": "permit"},
            # only for high-sensitivity resources
            {
                "type": "require_mfa",
                "on": "permit",
                "condition": {"==": [{"attr": "resource.attrs.sensitivity"}, "high"]},
            },
        ]
    )
    # low sensitivity: only ToS required, MFA skipped
    d = g.evaluate_sync(
        _S,
        Action("read"),
        _resource(sensitivity="low"),
        Context(attrs={"tos_accepted": True, "mfa": False}),
    )
    assert d.allowed is True

    # high sensitivity: ToS + MFA both required
    d2 = g.evaluate_sync(
        _S,
        Action("read"),
        _resource(sensitivity="high"),
        Context(attrs={"tos_accepted": True, "mfa": False}),
    )
    assert d2.allowed is False
    assert d2.reason == "obligation_failed"

    # high sensitivity, both met
    d3 = g.evaluate_sync(
        _S,
        Action("read"),
        _resource(sensitivity="high"),
        Context(attrs={"tos_accepted": True, "mfa": True}),
    )
    assert d3.allowed is True


# ---------------------------------------------------------------------------
# Async and batch APIs
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_evaluate_async_conditional_obligation():
    """evaluate_async correctly enforces conditional obligation."""
    g = _guard(
        [
            {
                "type": "require_mfa",
                "on": "permit",
                "condition": {"==": [{"attr": "resource.attrs.sensitivity"}, "high"]},
            }
        ]
    )
    d = await g.evaluate_async(
        _S,
        Action("read"),
        _resource(sensitivity="high"),
        Context(attrs={"mfa": False}),
    )
    assert d.allowed is False


@pytest.mark.asyncio
async def test_evaluate_batch_async_conditional_obligation():
    """evaluate_batch_async applies conditional obligations per-request."""
    g = _guard(
        [
            {
                "type": "require_mfa",
                "on": "permit",
                "condition": {"==": [{"attr": "resource.attrs.sensitivity"}, "high"]},
            }
        ]
    )
    results = await g.evaluate_batch_async(
        [
            (_S, Action("read"), _resource(sensitivity="high"), Context(attrs={"mfa": False})),
            (_S, Action("read"), _resource(sensitivity="low"), Context(attrs={"mfa": False})),
            (_S, Action("read"), _resource(sensitivity="high"), Context(attrs={"mfa": True})),
        ]
    )
    assert results[0].allowed is False  # high + no mfa → deny
    assert results[1].allowed is True  # low → mfa skipped → permit
    assert results[2].allowed is True  # high + mfa → permit


# ---------------------------------------------------------------------------
# Cache: env must come from the current request, not the cached raw decision
# ---------------------------------------------------------------------------


def test_cache_env_from_current_request():
    """Cached raw decision must not leak env between requests with different
    resource attributes — obligation condition re-evaluated per request."""
    g = Guard(
        {
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
            ]
        },
        cache=DefaultInMemoryCache(),
    )
    r_high = Resource(type="doc", id="d1", attrs={"sensitivity": "high"})
    r_low = Resource(type="doc", id="d2", attrs={"sensitivity": "low"})
    ctx_no_mfa = Context(attrs={"mfa": False})

    # Both requests hit different cache keys (different resource attrs)
    d1 = g.evaluate_sync(_S, Action("read"), r_high, ctx_no_mfa)
    assert d1.allowed is False

    d2 = g.evaluate_sync(_S, Action("read"), r_low, ctx_no_mfa)
    assert d2.allowed is True  # low sensitivity → mfa obligation skipped
