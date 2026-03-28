from collections.abc import Iterable, Sequence
from typing import Any

from .policy import evaluate as evaluate_policy
from .policyset import decide as decide_policyset


def _actions(rule: dict[str, Any]) -> tuple[str, ...]:
    acts_raw = rule.get("actions")
    if not isinstance(acts_raw, Iterable):
        return tuple()
    acts = [a for a in acts_raw if isinstance(a, str)]
    return tuple(acts)


def _resource_types(rule: dict[str, Any]) -> tuple[str | None, ...]:
    """Return declared resource types for the rule.

    None means 'wildcard/any type'.
    """
    r = rule.get("resource") or {}
    t = r.get("type")
    if t is None:
        return (None,)
    if isinstance(t, str):
        return (None,) if t == "*" else (t,)
    if isinstance(t, list):
        out: list[str | None] = []
        for x in t:
            if isinstance(x, str):
                out.append(None if x == "*" else x)
        return tuple(out) if out else (None,)
    return (None,)


def _has_id(rule: dict[str, Any]) -> bool:
    r = rule.get("resource") or {}
    return r.get("id") is not None


def _has_attrs(rule: dict[str, Any]) -> bool:
    r = rule.get("resource") or {}
    attrs = (
        r.get("attrs") or r.get("attributes") or {}
    )  # attributes is also accepted for backward compatibility
    return isinstance(attrs, dict) and len(attrs) > 0


def _type_matches(rule_types: Sequence[str | None], res_type: str | None) -> bool:
    if not rule_types:
        return True
    return (res_type in rule_types) or (None in rule_types)


def _categorize(rule: dict[str, Any], res_type: str | None) -> int | None:
    """Return priority bucket for the rule relative to resource.

    0 -> (type match) & id-specific
    1 -> (type match) & attrs constrained
    2 -> (type match) only
    3 -> wildcard type
    None -> not a candidate for this resource
    """
    rtypes = _resource_types(rule)
    if not _type_matches(rtypes, res_type):
        return None
    if res_type in rtypes and _has_id(rule):
        return 0
    if res_type in rtypes and _has_attrs(rule):
        return 1
    if res_type in rtypes:
        return 2
    return 3


def _action_matches(rule: dict[str, Any], action: str) -> bool:
    """Return True if the rule's actions list includes *action* or the wildcard ``*``."""
    acts_raw = rule.get("actions")
    if not isinstance(acts_raw, Iterable):
        return False
    return action in acts_raw or "*" in acts_raw


def _select_rules(
    all_rules: list[dict[str, Any]],
    candidates_by_action: list[dict[str, Any]],
    res_type: str | None,
    action: str,
    algo: str,
) -> list[dict[str, Any]]:
    """Return the rule list to pass to ``evaluate_policy`` for this request.

    Algorithm-specific contract
    ---------------------------

    ``first-applicable``
        The interpreter evaluates rules in **declaration order** and stops at
        the first match.  Any re-ordering -- including the ``by_action`` /
        ``star_rules`` split used for the other algorithms -- would silently
        change which rule fires first and produce a wrong decision.

        For this algorithm the function scans the original ``all_rules`` list
        (declaration order) and keeps only those rules whose action and
        resource type are compatible with the current request.  The
        interpreter then applies its full matching logic (including condition
        evaluation) in that preserved order.

    ``deny-overrides`` (default), ``permit-overrides``, and unknown algorithms
        The interpreter scans all candidates and applies the combining
        algorithm.  A rule in a less-specific bucket must never be discarded:

        * Under ``deny-overrides`` a wildcard deny (bucket 3) must override
          an id-specific permit (bucket 0) -- the core security bug fixed in
          v1.9.3.
        * Under ``permit-overrides`` a type-level permit (bucket 2) must
          override an id-specific deny (bucket 0), because any matching permit
          wins the full evaluation.

        Candidates (already filtered by action match) are therefore **merged
        across all resource-specificity buckets** in order (0 -> 3), with
        deduplication by object identity.  Within each bucket the original
        declaration order is preserved.
    """
    if algo == "first-applicable":
        # Walk the full policy rule list in declaration order, keeping only
        # rules whose action and resource type are compatible.  Declaration
        # order is the contract for first-applicable.
        filtered: list[dict[str, Any]] = []
        seen: set[int] = set()
        for r in all_rules:
            oid = id(r)
            if oid in seen:
                continue
            seen.add(oid)
            if not _action_matches(r, action):
                continue
            if _categorize(r, res_type) is not None:
                filtered.append(r)
        return filtered

    # deny-overrides, permit-overrides, and unknown algorithms:
    # Merge all resource-specificity buckets so that no rule is silently dropped.
    buckets: list[list[dict[str, Any]]] = [[], [], [], []]
    for r in candidates_by_action:
        cat = _categorize(r, res_type)
        if cat is None:
            continue
        buckets[cat].append(r)

    merged: list[dict[str, Any]] = []
    seen_m: set[int] = set()
    for bucket in buckets:
        for r in bucket:
            oid = id(r)
            if oid not in seen_m:
                merged.append(r)
                seen_m.add(oid)
    return merged


def compile(policy: dict[str, Any]) -> Any:
    """Compile a policy into a fast decision function with correct cross-bucket semantics.

    Resource-specificity buckets
    ----------------------------
    Rules are categorised by how specifically they constrain the resource:

    =======  ====================================================
    Bucket   Description
    =======  ====================================================
    0        Type match **and** id-specific
    1        Type match **and** attrs-constrained
    2        Type match only
    3        Wildcard type (``resource: {}`` or ``type: "*"``)
    =======  ====================================================

    Rule selection per algorithm
    ----------------------------
    ``first-applicable``
        Rules are filtered to those whose **action and resource type** are
        compatible with the request, then delivered to the interpreter in
        their **original declaration order**.  The ``by_action`` / ``star_rules``
        split is deliberately bypassed for this algorithm because it changes
        declaration order and would produce incorrect decisions.

    ``deny-overrides`` (default), ``permit-overrides``, and unknown algorithms
        Rules from **all matching resource-specificity buckets** are merged in
        specificity order (bucket 0 -> 3) before being handed to the
        interpreter.  This ensures:

        * A deny rule at any specificity level (e.g. wildcard) correctly
          overrides a permit rule at a more specific level under
          ``deny-overrides``.
        * A permit rule at any specificity level correctly overrides a deny
          rule at a more specific level under ``permit-overrides``.

    For policy *sets* the function delegates to ``policyset.decide``.
    """
    # PolicySet: delegate to policyset evaluator (no compilation here)
    if "policies" in policy:
        return lambda env: decide_policyset(policy, env)

    all_rules: list[dict[str, Any]] = list(policy.get("rules") or [])
    # Default must match policy.evaluate() -- deny-overrides (conservative).
    algo = (policy.get("algorithm") or "deny-overrides").lower()

    # Pre-index rules by action for deny-overrides / permit-overrides fast path.
    # '*' rules are kept separately and appended after specific-action rules.
    by_action: dict[str, list[dict[str, Any]]] = {}
    star_rules: list[dict[str, Any]] = []
    for rule in all_rules:
        acts = _actions(rule)
        if not acts:
            continue
        if "*" in acts:
            star_rules.append(rule)
        for a in acts:
            if a == "*":
                continue
            by_action.setdefault(a, []).append(rule)

    def decide(env: dict[str, Any]) -> dict[str, Any]:
        action_val = env.get("action")
        action: str = str(action_val) if action_val is not None else ""
        res = env.get("resource") or {}
        _rt = res.get("type")
        res_type: str | None = None if _rt is None else str(_rt)

        # Build the action-matched candidate list (used for non-first-applicable).
        candidates: list[dict[str, Any]] = []
        seen: set[int] = set()
        for r in by_action.get(action, []):
            rid = id(r)
            if rid not in seen:
                candidates.append(r)
                seen.add(rid)
        for r in star_rules:
            rid = id(r)
            if rid not in seen:
                candidates.append(r)
                seen.add(rid)

        selected = _select_rules(all_rules, candidates, res_type, action, algo)
        compiled_policy = {"algorithm": algo, "rules": selected}
        return evaluate_policy(compiled_policy, env)

    return decide


__all__ = ["compile"]
