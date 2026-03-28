"""Regression tests for the compiler cross-bucket security bug (fixed in 1.9.3).

Bug summary
-----------
The compiled fast-path selected only the *most specific* non-empty resource
bucket and silently discarded all less-specific buckets.  Under
``deny-overrides`` this is a security bypass: a deny rule in a broader bucket
(e.g. wildcard ``resource: {}``) must still override a permit rule in a more
specific bucket (e.g. ``resource: {type:"doc", id:"42"}``).

Three concrete bypass scenarios were identified:

1. Wildcard deny (bucket 3) vs type-specific permit (bucket 2).
2. Type-level deny (bucket 2) vs id-specific permit (bucket 0).
3. Attribute-constrained deny (bucket 1) vs id-specific permit (bucket 0).

In every case the compiled path returned ``permit`` while the authoritative
interpreter returned ``deny``.

Root cause and fix
------------------
The original ``compile()`` used a single-bucket optimisation for all
algorithms: pick the first non-empty bucket and discard the rest.  This
optimisation is not semantically valid for any combining algorithm when rules
span multiple specificity levels:

* ``deny-overrides``: a wildcard deny (bucket 3) is discarded when a
  more-specific permit (bucket 0) exists — security bypass.
* ``permit-overrides``: a type-level permit (bucket 2) is discarded when a
  more-specific deny (bucket 0) exists — incorrect deny.
* ``first-applicable``: the ``by_action`` / ``star_rules`` split changes
  the declaration order that ``first-applicable`` semantics require.

The fix introduces ``_select_rules()``:

* For ``deny-overrides``, ``permit-overrides``, and unknown algorithms: all
  matching resource-specificity buckets are merged in specificity order so
  that no rule is silently dropped.
* For ``first-applicable``: the original policy rule list is scanned in
  declaration order (the ``by_action`` split is bypassed) and rules are
  filtered by action / resource-type compatibility only.

In all cases the compiled decision is now guaranteed to be identical to the
authoritative ``evaluate_policy`` interpreter.
"""

import random

import pytest

from rbacx.core.compiler import _select_rules
from rbacx.core.compiler import compile as compile_policy
from rbacx.core.policy import evaluate as eval_policy

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _env(
    action: str = "read",
    res_type: str = "doc",
    res_id: str = "42",
    attrs: dict | None = None,
) -> dict:
    return {
        "action": action,
        "resource": {"type": res_type, "id": res_id, "attrs": attrs or {}},
        "subject": {"id": "u", "roles": [], "attrs": {}},
        "context": {},
    }


def _both(policy: dict, env: dict) -> tuple[str, str]:
    """Return (compiled_decision, interpreted_decision)."""
    compiled = compile_policy(policy)(env)["decision"]
    interpreted = eval_policy(policy, env)["decision"]
    return compiled, interpreted


# ---------------------------------------------------------------------------
# Core regression: three deny-overrides bypass scenarios
# ---------------------------------------------------------------------------


class TestDenyOverridesCrossBucketBypass:
    """Compiled and interpreted paths must agree on deny-overrides cross-bucket cases."""

    def test_wildcard_deny_bucket3_vs_type_permit_bucket2(self) -> None:
        """Wildcard deny (resource:{}) must override a type-specific permit.

        Real-world scenario: emergency lock-down via a global deny rule.
        Before the fix the compiled path returned permit.
        """
        policy = {
            "algorithm": "deny-overrides",
            "rules": [
                {"id": "deny_all", "effect": "deny", "actions": ["*"], "resource": {}},
                {
                    "id": "permit_doc",
                    "effect": "permit",
                    "actions": ["read"],
                    "resource": {"type": "doc"},
                },
            ],
        }
        env = _env(action="read", res_type="doc", res_id="secret")
        compiled, interpreted = _both(policy, env)

        assert compiled == interpreted, (
            f"compiled={compiled!r} but interpreted={interpreted!r}: "
            "wildcard deny must not be discarded by bucket optimisation"
        )
        assert compiled == "deny"

    def test_type_deny_bucket2_vs_id_permit_bucket0(self) -> None:
        """Type-level deny must override an id-specific permit.

        Real-world scenario: all documents of a type are locked (audit), but
        an id-specific permit exists for one document.
        Before the fix the compiled path returned permit.
        """
        policy = {
            "algorithm": "deny-overrides",
            "rules": [
                {
                    "id": "deny_type",
                    "effect": "deny",
                    "actions": ["*"],
                    "resource": {"type": "doc"},
                },
                {
                    "id": "permit_id",
                    "effect": "permit",
                    "actions": ["read"],
                    "resource": {"type": "doc", "id": "42"},
                },
            ],
        }
        env = _env(action="read", res_type="doc", res_id="42")
        compiled, interpreted = _both(policy, env)

        assert compiled == interpreted, (
            f"compiled={compiled!r} but interpreted={interpreted!r}: "
            "type-level deny must not be discarded by bucket optimisation"
        )
        assert compiled == "deny"

    def test_attrs_deny_bucket1_vs_id_permit_bucket0(self) -> None:
        """Attribute-constrained deny must override an id-specific permit.

        Real-world scenario: GDPR/retention — archived documents are forbidden
        even if a per-id permit exists.
        Before the fix the compiled path returned permit.
        """
        policy = {
            "algorithm": "deny-overrides",
            "rules": [
                {
                    "id": "deny_archived",
                    "effect": "deny",
                    "actions": ["*"],
                    "resource": {"type": "doc", "attrs": {"archived": True}},
                },
                {
                    "id": "permit_id",
                    "effect": "permit",
                    "actions": ["read"],
                    "resource": {"type": "doc", "id": "42"},
                },
            ],
        }
        env = _env(action="read", res_type="doc", res_id="42", attrs={"archived": True})
        compiled, interpreted = _both(policy, env)

        assert compiled == interpreted, (
            f"compiled={compiled!r} but interpreted={interpreted!r}: "
            "attrs-constrained deny must not be discarded by bucket optimisation"
        )
        assert compiled == "deny"


# ---------------------------------------------------------------------------
# permit-overrides cross-bucket correctness
# ---------------------------------------------------------------------------


class TestPermitOverridesCrossBucket:
    """Under permit-overrides any matching permit in any bucket must win."""

    def test_type_permit_bucket2_vs_id_deny_bucket0(self) -> None:
        """A type-level permit must override an id-specific deny.

        permit-overrides semantics: any matching permit wins regardless of
        how specifically the permit rule is written.
        """
        policy = {
            "algorithm": "permit-overrides",
            "rules": [
                {
                    "id": "deny_id",
                    "effect": "deny",
                    "actions": ["read"],
                    "resource": {"type": "doc", "id": "42"},
                },
                {
                    "id": "permit_type",
                    "effect": "permit",
                    "actions": ["read"],
                    "resource": {"type": "doc"},
                },
            ],
        }
        env = _env(action="read", res_type="doc", res_id="42")
        compiled, interpreted = _both(policy, env)

        assert compiled == interpreted, (
            f"compiled={compiled!r} but interpreted={interpreted!r}: "
            "type-level permit must not be discarded under permit-overrides"
        )
        assert compiled == "permit"

    def test_wildcard_permit_bucket3_vs_type_deny_bucket2(self) -> None:
        """A wildcard permit must override a type-level deny under permit-overrides."""
        policy = {
            "algorithm": "permit-overrides",
            "rules": [
                {
                    "id": "deny_type",
                    "effect": "deny",
                    "actions": ["read"],
                    "resource": {"type": "doc"},
                },
                {
                    "id": "permit_all",
                    "effect": "permit",
                    "actions": ["*"],
                    "resource": {},
                },
            ],
        }
        env = _env(action="read", res_type="doc", res_id="1")
        compiled, interpreted = _both(policy, env)

        assert compiled == interpreted
        assert compiled == "permit"

    def test_permit_overrides_only_denies_returns_deny(self) -> None:
        """When only deny rules match, permit-overrides must still return deny."""
        policy = {
            "algorithm": "permit-overrides",
            "rules": [
                {
                    "id": "d1",
                    "effect": "deny",
                    "actions": ["read"],
                    "resource": {"type": "doc"},
                },
            ],
        }
        compiled, interpreted = _both(policy, _env())
        assert compiled == interpreted == "deny"


# ---------------------------------------------------------------------------
# first-applicable: declaration order must be preserved
# ---------------------------------------------------------------------------


class TestFirstApplicableDeclarationOrder:
    """Under first-applicable the original declaration order must be respected."""

    def test_wildcard_permit_before_type_deny(self) -> None:
        """A wildcard permit declared first must win even if a type deny comes later."""
        policy = {
            "algorithm": "first-applicable",
            "rules": [
                {"id": "permit_all", "effect": "permit", "actions": ["*"], "resource": {}},
                {
                    "id": "deny_type",
                    "effect": "deny",
                    "actions": ["read"],
                    "resource": {"type": "doc"},
                },
            ],
        }
        env = _env(action="read", res_type="doc", res_id="1")
        compiled, interpreted = _both(policy, env)

        assert compiled == interpreted, (
            f"compiled={compiled!r} but interpreted={interpreted!r}: "
            "first-applicable must respect declaration order"
        )
        assert compiled == "permit"
        assert compile_policy(policy)(env)["rule_id"] == "permit_all"

    def test_type_deny_before_id_permit(self) -> None:
        """A type-level deny declared first must stop evaluation before an id permit."""
        policy = {
            "algorithm": "first-applicable",
            "rules": [
                {
                    "id": "deny_type",
                    "effect": "deny",
                    "actions": ["read"],
                    "resource": {"type": "doc"},
                },
                {
                    "id": "permit_id",
                    "effect": "permit",
                    "actions": ["read"],
                    "resource": {"type": "doc", "id": "42"},
                },
            ],
        }
        env = _env(action="read", res_type="doc", res_id="42")
        compiled, interpreted = _both(policy, env)

        assert compiled == interpreted
        assert compiled == "deny"
        assert compile_policy(policy)(env)["rule_id"] == "deny_type"

    def test_star_action_rule_before_specific_action_rule(self) -> None:
        """A wildcard-action rule declared first must fire before a specific-action rule.

        This exercises the by_action/star_rules ordering fix: the star rule
        must not be moved after the specific-action rule merely because it
        was collected via the star_rules list.
        """
        policy = {
            "algorithm": "first-applicable",
            "rules": [
                # wildcard action — collected via star_rules in old code, moved last
                {"id": "deny_star", "effect": "deny", "actions": ["*"], "resource": {}},
                # specific action — collected via by_action['read'], came first in old code
                {
                    "id": "permit_read",
                    "effect": "permit",
                    "actions": ["read"],
                    "resource": {"type": "doc"},
                },
            ],
        }
        env = _env(action="read", res_type="doc", res_id="1")
        compiled, interpreted = _both(policy, env)

        assert compiled == interpreted, (
            f"compiled={compiled!r} but interpreted={interpreted!r}: "
            "star-action rule declared first must be evaluated first"
        )
        assert compiled == "deny"
        assert compile_policy(policy)(env)["rule_id"] == "deny_star"


# ---------------------------------------------------------------------------
# Unknown algorithm — treated conservatively
# ---------------------------------------------------------------------------


def test_unknown_algorithm_merges_all_buckets() -> None:
    """An unrecognised algorithm must be treated conservatively (all buckets merged).

    This ensures that unknown algorithms cannot accidentally bypass deny rules
    through the bucket optimisation path.
    """
    policy = {
        "algorithm": "some-future-algo",
        "rules": [
            {"id": "deny_wild", "effect": "deny", "actions": ["*"], "resource": {}},
            {
                "id": "permit_id",
                "effect": "permit",
                "actions": ["read"],
                "resource": {"type": "doc", "id": "1"},
            },
        ],
    }
    env = _env(action="read", res_type="doc", res_id="1")
    compiled, interpreted = _both(policy, env)
    # Both paths use the same unknown-algorithm fallback — they must agree.
    assert compiled == interpreted


# ---------------------------------------------------------------------------
# Equivalence property: compiled == interpreted for 500 random policies
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("seed", [0, 1, 2, 3, 4])
def test_compiled_equals_interpreted_random_policies(seed: int) -> None:
    """Compiled and interpreted decisions must be identical for random policies.

    Each parametrised seed generates 100 random policies across all three
    algorithms and asserts that the compiled fast-path produces the same
    decision as the authoritative interpreter.
    """
    rng = random.Random(seed)
    env = {
        "action": "read",
        "resource": {"type": "doc", "id": "1", "attrs": {}},
        "subject": {"id": "u", "roles": [], "attrs": {}},
        "context": {},
    }

    for _ in range(100):
        algo = rng.choice(["deny-overrides", "permit-overrides", "first-applicable"])
        rules = []
        for i in range(rng.randint(1, 6)):
            rt = rng.choice(["doc", "img", "*", None])
            res: dict = {} if rt is None else {"type": rt}
            if rt and rt != "*":
                roll = rng.random()
                if roll > 0.65:
                    res["id"] = rng.choice(["1", "2", "X"])
                elif roll > 0.40:
                    res["attrs"] = {"k": rng.choice([1, 2])}
            rules.append(
                {
                    "id": f"r{i}",
                    "effect": rng.choice(["permit", "deny"]),
                    "actions": [rng.choice(["read", "*"])],
                    "resource": res,
                }
            )
        policy = {"algorithm": algo, "rules": rules}

        c = compile_policy(policy)(env)["decision"]
        i = eval_policy(policy, env)["decision"]
        assert c == i, (
            f"seed={seed} algo={algo!r}: compiled={c!r} interpreted={i!r}\n" f"rules={rules}"
        )


# ---------------------------------------------------------------------------
# Unit tests for _select_rules directly
# ---------------------------------------------------------------------------


class TestSelectRules:
    """Unit tests for the _select_rules helper."""

    def _rule(self, rid: str, effect: str, res: dict, actions: list | None = None) -> dict:
        return {
            "id": rid,
            "effect": effect,
            "actions": actions or ["read"],
            "resource": res,
        }

    def test_deny_overrides_merges_all_buckets_in_specificity_order(self) -> None:
        """All four buckets must be merged, most-specific (0) first."""
        r0 = self._rule("id-specific", "permit", {"type": "doc", "id": "1"})
        r1 = self._rule("attrs", "deny", {"type": "doc", "attrs": {"k": 1}})
        r2 = self._rule("type-only", "permit", {"type": "doc"})
        r3 = self._rule("wildcard", "deny", {})

        selected = _select_rules(
            [r0, r1, r2, r3], [r0, r1, r2, r3], "doc", "read", "deny-overrides"
        )

        ids = [r["id"] for r in selected]
        assert set(ids) == {"id-specific", "attrs", "type-only", "wildcard"}
        assert ids.index("id-specific") < ids.index("attrs")
        assert ids.index("attrs") < ids.index("type-only")
        assert ids.index("type-only") < ids.index("wildcard")

    def test_deny_overrides_excludes_type_mismatched_rules(self) -> None:
        """Rules whose type cannot match the request resource must be excluded."""
        r_img = self._rule("img-only", "deny", {"type": "img"})
        r_doc = self._rule("doc-only", "permit", {"type": "doc"})

        selected = _select_rules([r_img, r_doc], [r_img, r_doc], "doc", "read", "deny-overrides")
        ids = [r["id"] for r in selected]
        assert "doc-only" in ids
        assert "img-only" not in ids

    def test_deny_overrides_deduplicates_same_object(self) -> None:
        """The same rule object must not appear twice in the output."""
        r = self._rule("dup", "deny", {"type": "doc"})
        selected = _select_rules([r, r], [r, r], "doc", "read", "deny-overrides")
        assert len(selected) == 1

    def test_deny_overrides_empty_candidates_returns_empty(self) -> None:
        assert _select_rules([], [], "doc", "read", "deny-overrides") == []

    def test_permit_overrides_merges_all_buckets(self) -> None:
        """permit-overrides must also include rules from all buckets."""
        r0 = self._rule("id-specific", "deny", {"type": "doc", "id": "1"})
        r3 = self._rule("wildcard", "permit", {})

        selected = _select_rules([r0, r3], [r0, r3], "doc", "read", "permit-overrides")
        ids = [r["id"] for r in selected]
        assert "id-specific" in ids
        assert "wildcard" in ids

    def test_first_applicable_preserves_declaration_order(self) -> None:
        """first-applicable must return rules in the original all_rules order."""
        r_wild = self._rule("wildcard", "deny", {}, actions=["*"])
        r_type = self._rule("type-only", "permit", {"type": "doc"})
        r_id = self._rule("id-specific", "permit", {"type": "doc", "id": "1"})

        # Declaration order: wildcard, type, id-specific
        all_rules = [r_wild, r_type, r_id]
        # by_action would normally put r_type and r_id first, wildcard last
        candidates_wrong_order = [r_type, r_id, r_wild]

        selected = _select_rules(
            all_rules, candidates_wrong_order, "doc", "read", "first-applicable"
        )
        ids = [r["id"] for r in selected]

        assert ids[0] == "wildcard", "wildcard declared first must appear first"
        assert ids[1] == "type-only"
        assert ids[2] == "id-specific"

    def test_first_applicable_excludes_type_mismatched_rules(self) -> None:
        """first-applicable must filter out type-incompatible rules."""
        r_img = self._rule("img", "deny", {"type": "img"})
        r_doc = self._rule("doc", "permit", {"type": "doc"})

        selected = _select_rules([r_img, r_doc], [r_doc], "doc", "read", "first-applicable")
        ids = [r["id"] for r in selected]
        assert "doc" in ids
        assert "img" not in ids

    def test_first_applicable_excludes_action_mismatched_rules(self) -> None:
        """first-applicable must filter out rules whose actions do not match."""
        r_write = self._rule("write-only", "deny", {}, actions=["write"])
        r_read = self._rule("read-ok", "permit", {}, actions=["read"])

        selected = _select_rules([r_write, r_read], [r_read], "doc", "read", "first-applicable")
        ids = [r["id"] for r in selected]
        assert "read-ok" in ids
        assert "write-only" not in ids

    @pytest.mark.parametrize("algo", ["deny-overrides", "permit-overrides", "unknown-algo", ""])
    def test_non_first_applicable_includes_wildcard_deny(self, algo: str) -> None:
        """All non-first-applicable algorithms must include wildcard deny rules."""
        r_permit = self._rule("permit", "permit", {"type": "doc", "id": "99"})
        r_deny = self._rule("deny-wild", "deny", {})

        selected = _select_rules([r_permit, r_deny], [r_permit, r_deny], "doc", "read", algo)
        ids = [r["id"] for r in selected]
        assert "deny-wild" in ids, f"wildcard deny must be included for algo={algo!r}"
