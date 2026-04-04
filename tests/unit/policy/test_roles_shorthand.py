"""Unit tests for the ``roles`` shorthand field on rules.

``{"roles": ["admin", "editor"]}`` is syntactic sugar for:
``{"condition": {"hasAny": [{"attr": "subject.roles"}, ["admin", "editor"]]}}``

When both ``roles`` and ``condition`` are present they are combined with AND.
"""

import pytest

from rbacx import Action, Context, Guard, Resource, Subject
from rbacx.dsl.lint import analyze_policy

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_R = Resource(type="doc", id="d1")
_CTX = Context()

_S_ADMIN = Subject(id="u1", roles=["admin"])
_S_EDITOR = Subject(id="u2", roles=["editor"])
_S_VIEWER = Subject(id="u3", roles=["viewer"])
_S_USER = Subject(id="u4", roles=["user"])


def _guard(rules, algo="deny-overrides"):
    return Guard({"algorithm": algo, "rules": rules})


def _policy(rules, algo="deny-overrides"):
    return {"algorithm": algo, "rules": rules}


# ---------------------------------------------------------------------------
# Basic permit via roles shorthand
# ---------------------------------------------------------------------------


def test_roles_only_matching_role_permits():
    """Subjects whose roles list intersects the rule's ``roles`` are permitted."""
    g = _guard(
        [
            {
                "id": "r1",
                "effect": "permit",
                "actions": ["read"],
                "resource": {"type": "doc"},
                "roles": ["admin", "editor"],
            }
        ]
    )

    assert g.evaluate_sync(_S_ADMIN, Action("read"), _R, _CTX).allowed is True
    assert g.evaluate_sync(_S_EDITOR, Action("read"), _R, _CTX).allowed is True


def test_roles_only_non_matching_role_denies():
    """Subjects without any of the listed roles are denied."""
    g = _guard(
        [
            {
                "id": "r1",
                "effect": "permit",
                "actions": ["read"],
                "resource": {"type": "doc"},
                "roles": ["admin", "editor"],
            }
        ]
    )

    assert g.evaluate_sync(_S_VIEWER, Action("read"), _R, _CTX).allowed is False


# ---------------------------------------------------------------------------
# roles + condition on a different attribute (AND semantics)
# ---------------------------------------------------------------------------


def test_roles_plus_condition_other_attr_both_must_pass():
    """When ``roles`` and ``condition`` target different attributes,
    both must be satisfied for the rule to match."""
    g = _guard(
        [
            {
                "id": "r1",
                "effect": "permit",
                "actions": ["read"],
                "resource": {"type": "doc"},
                "roles": ["admin"],
                "condition": {"==": [{"attr": "resource.attrs.visibility"}, "public"]},
            }
        ]
    )

    R_pub = Resource(type="doc", attrs={"visibility": "public"})
    R_priv = Resource(type="doc", attrs={"visibility": "private"})

    assert g.evaluate_sync(_S_ADMIN, Action("read"), R_pub, _CTX).allowed is True
    assert g.evaluate_sync(_S_ADMIN, Action("read"), R_priv, _CTX).allowed is False
    assert g.evaluate_sync(_S_VIEWER, Action("read"), R_pub, _CTX).allowed is False


# ---------------------------------------------------------------------------
# Conflict: roles + condition both constrain subject.roles
# Engine takes AND (intersection — most restrictive)
# ---------------------------------------------------------------------------


def test_roles_condition_conflict_and_is_intersection():
    """When ``roles`` and ``condition`` both constrain subject.roles the engine
    combines them with AND.  The result is the intersection — only subjects
    that satisfy BOTH constraints are permitted.

    Example: roles=[admin] AND hasAny(subject.roles, [admin, user])
    → effectively only admin, because user does not satisfy roles=[admin].
    """
    g = _guard(
        [
            {
                "id": "r1",
                "effect": "permit",
                "actions": ["read"],
                "resource": {"type": "doc"},
                "roles": ["admin"],
                "condition": {"hasAny": [{"attr": "subject.roles"}, ["admin", "user"]]},
            }
        ]
    )

    # admin satisfies both → permit
    assert g.evaluate_sync(_S_ADMIN, Action("read"), _R, _CTX).allowed is True
    # user satisfies condition but NOT roles shorthand → deny
    assert g.evaluate_sync(_S_USER, Action("read"), _R, _CTX).allowed is False
    # viewer satisfies neither → deny
    assert g.evaluate_sync(_S_VIEWER, Action("read"), _R, _CTX).allowed is False


# ---------------------------------------------------------------------------
# Backward compatibility — no roles field
# ---------------------------------------------------------------------------


def test_no_roles_condition_only_unchanged():
    """Rules without ``roles`` continue to work exactly as before."""
    g = _guard(
        [
            {
                "id": "r1",
                "effect": "permit",
                "actions": ["read"],
                "resource": {"type": "doc"},
                "condition": {"hasAny": [{"attr": "subject.roles"}, ["admin"]]},
            }
        ]
    )

    assert g.evaluate_sync(_S_ADMIN, Action("read"), _R, _CTX).allowed is True
    assert g.evaluate_sync(_S_VIEWER, Action("read"), _R, _CTX).allowed is False


def test_no_roles_no_condition_unchanged():
    """Rules with neither ``roles`` nor ``condition`` match any subject."""
    g = _guard([{"id": "r1", "effect": "permit", "actions": ["read"], "resource": {"type": "doc"}}])

    assert g.evaluate_sync(_S_VIEWER, Action("read"), _R, _CTX).allowed is True


def test_roles_empty_list_not_applied():
    """An empty ``roles`` list is falsy — shorthand is not applied and the
    rule behaves as if ``roles`` were absent."""
    g = _guard(
        [
            {
                "id": "r1",
                "effect": "permit",
                "actions": ["read"],
                "resource": {"type": "doc"},
                "roles": [],
            }
        ]
    )

    assert g.evaluate_sync(_S_VIEWER, Action("read"), _R, _CTX).allowed is True


# ---------------------------------------------------------------------------
# roles on deny rules
# ---------------------------------------------------------------------------


def test_roles_shorthand_on_deny_rule():
    """``roles`` shorthand works on deny rules too — only the matching role
    is denied; other roles fall through to no_match (also deny by default)."""
    g = _guard(
        [
            {
                "id": "r1",
                "effect": "deny",
                "actions": ["delete"],
                "resource": {"type": "doc"},
                "roles": ["viewer"],
            }
        ]
    )

    assert g.evaluate_sync(_S_VIEWER, Action("delete"), _R, _CTX).allowed is False
    # admin: roles shorthand fails → rule skipped → no_match → deny
    assert g.evaluate_sync(_S_ADMIN, Action("delete"), _R, _CTX).allowed is False


# ---------------------------------------------------------------------------
# Async and batch
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_roles_shorthand_evaluate_async():
    """evaluate_async respects roles shorthand."""
    g = _guard(
        [
            {
                "id": "r1",
                "effect": "permit",
                "actions": ["read"],
                "resource": {"type": "doc"},
                "roles": ["admin"],
            }
        ]
    )

    d1 = await g.evaluate_async(_S_ADMIN, Action("read"), _R, _CTX)
    d2 = await g.evaluate_async(_S_VIEWER, Action("read"), _R, _CTX)
    assert d1.allowed is True
    assert d2.allowed is False


@pytest.mark.asyncio
async def test_roles_shorthand_batch_async():
    """evaluate_batch_async evaluates roles shorthand per request."""
    g = _guard(
        [
            {
                "id": "r1",
                "effect": "permit",
                "actions": ["read"],
                "resource": {"type": "doc"},
                "roles": ["admin"],
            }
        ]
    )

    results = await g.evaluate_batch_async(
        [
            (_S_ADMIN, Action("read"), _R, _CTX),
            (_S_VIEWER, Action("read"), _R, _CTX),
        ]
    )
    assert results[0].allowed is True
    assert results[1].allowed is False


# ---------------------------------------------------------------------------
# explain=True — trace shows condition_mismatch for roles fail
# ---------------------------------------------------------------------------


def test_roles_shorthand_trace_on_mismatch():
    """When ``roles`` shorthand fails the trace records ``condition_mismatch``
    (the shorthand is expanded to a condition internally)."""
    g = _guard(
        [
            {
                "id": "r1",
                "effect": "permit",
                "actions": ["read"],
                "resource": {"type": "doc"},
                "roles": ["admin"],
            }
        ]
    )

    d = g.evaluate_sync(_S_VIEWER, Action("read"), _R, _CTX, explain=True)
    assert d.allowed is False
    assert d.trace is not None and len(d.trace) == 1
    assert d.trace[0].skip_reason == "condition_mismatch"


# ---------------------------------------------------------------------------
# Compiled fast-path
# ---------------------------------------------------------------------------


def test_roles_shorthand_compiled_path():
    """Guard uses the compiled fast-path by default; roles shorthand must
    work correctly through it."""
    g = _guard(
        [
            {
                "id": "r1",
                "effect": "permit",
                "actions": ["read"],
                "resource": {"type": "doc"},
                "roles": ["admin"],
            }
        ]
    )

    assert g._compiled is not None, "compiler should be active"
    assert g.evaluate_sync(_S_ADMIN, Action("read"), _R, _CTX).allowed is True
    assert g.evaluate_sync(_S_VIEWER, Action("read"), _R, _CTX).allowed is False


# ---------------------------------------------------------------------------
# Linter: ROLES_CONDITION_OVERLAP
# ---------------------------------------------------------------------------


def test_lint_no_overlap_no_warning():
    """No warning when ``condition`` does not reference ``subject.roles``."""
    policy = _policy(
        [
            {
                "id": "r1",
                "effect": "permit",
                "actions": ["read"],
                "resource": {"type": "doc"},
                "roles": ["admin"],
                "condition": {"==": [{"attr": "resource.attrs.type"}, "report"]},
            }
        ]
    )
    codes = [i["code"] for i in analyze_policy(policy)]
    assert "ROLES_CONDITION_OVERLAP" not in codes


def test_lint_overlap_hasany():
    """ROLES_CONDITION_OVERLAP when condition uses hasAny on subject.roles."""
    policy = _policy(
        [
            {
                "id": "r1",
                "effect": "permit",
                "actions": ["read"],
                "resource": {"type": "doc"},
                "roles": ["admin"],
                "condition": {"hasAny": [{"attr": "subject.roles"}, ["admin", "user"]]},
            }
        ]
    )
    issues = analyze_policy(policy)
    codes = [i["code"] for i in issues]
    assert "ROLES_CONDITION_OVERLAP" in codes
    overlap = next(i for i in issues if i["code"] == "ROLES_CONDITION_OVERLAP")
    assert overlap["id"] == "r1"
    assert "AND" in overlap["message"]


def test_lint_overlap_eq():
    """ROLES_CONDITION_OVERLAP when condition uses == on subject.roles."""
    policy = _policy(
        [
            {
                "id": "r1",
                "effect": "permit",
                "actions": ["read"],
                "resource": {"type": "doc"},
                "roles": ["admin"],
                "condition": {"==": [{"attr": "subject.roles"}, "admin"]},
            }
        ]
    )
    codes = [i["code"] for i in analyze_policy(policy)]
    assert "ROLES_CONDITION_OVERLAP" in codes


def test_lint_overlap_nested_in_and():
    """ROLES_CONDITION_OVERLAP is detected when the subject.roles reference
    is nested inside an ``and`` subtree."""
    policy = _policy(
        [
            {
                "id": "r1",
                "effect": "permit",
                "actions": ["read"],
                "resource": {"type": "doc"},
                "roles": ["admin"],
                "condition": {
                    "and": [
                        {"==": [{"attr": "resource.attrs.type"}, "report"]},
                        {"hasAny": [{"attr": "subject.roles"}, ["admin", "user"]]},
                    ]
                },
            }
        ]
    )
    codes = [i["code"] for i in analyze_policy(policy)]
    assert "ROLES_CONDITION_OVERLAP" in codes


def test_lint_overlap_nested_in_not():
    """ROLES_CONDITION_OVERLAP is detected inside a ``not`` subtree."""
    policy = _policy(
        [
            {
                "id": "r1",
                "effect": "permit",
                "actions": ["read"],
                "resource": {"type": "doc"},
                "roles": ["admin"],
                "condition": {"not": {"hasAny": [{"attr": "subject.roles"}, ["viewer"]]}},
            }
        ]
    )
    codes = [i["code"] for i in analyze_policy(policy)]
    assert "ROLES_CONDITION_OVERLAP" in codes


def test_lint_no_overlap_when_no_roles_key():
    """No ROLES_CONDITION_OVERLAP when rule has no ``roles`` key even if
    condition references subject.roles (that is standard usage)."""
    policy = _policy(
        [
            {
                "id": "r1",
                "effect": "permit",
                "actions": ["read"],
                "resource": {"type": "doc"},
                "condition": {"hasAny": [{"attr": "subject.roles"}, ["admin"]]},
            }
        ]
    )
    codes = [i["code"] for i in analyze_policy(policy)]
    assert "ROLES_CONDITION_OVERLAP" not in codes


# ---------------------------------------------------------------------------
# RoleResolver interaction
# ---------------------------------------------------------------------------


def test_roles_shorthand_with_role_resolver():
    """``roles`` shorthand checks the expanded role list produced by
    ``RoleResolver``, not the raw ``Subject.roles``.

    Example: ``manager`` inherits ``employee`` via ``StaticRoleResolver``.
    A rule with ``roles: [employee]`` must permit a ``manager`` subject because
    after expansion ``subject.roles`` contains both ``manager`` and ``employee``.
    """
    from rbacx.core.roles import StaticRoleResolver

    resolver = StaticRoleResolver({"manager": ["employee"]})
    g = Guard(
        {
            "algorithm": "deny-overrides",
            "rules": [
                {
                    "id": "r1",
                    "effect": "permit",
                    "actions": ["read"],
                    "resource": {"type": "doc"},
                    "roles": ["employee"],
                },
            ],
        },
        role_resolver=resolver,
    )
    R = Resource(type="doc")

    # manager expands to [employee, manager] → employee present → permit
    assert (
        g.evaluate_sync(Subject(id="u1", roles=["manager"]), Action("read"), R, _CTX).allowed
        is True
    )

    # viewer does not expand to employee → deny
    assert (
        g.evaluate_sync(Subject(id="u2", roles=["viewer"]), Action("read"), R, _CTX).allowed
        is False
    )
