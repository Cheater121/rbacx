from __future__ import annotations

from typing import Any, Dict, Iterable, List, Sequence, Tuple

from .policy import evaluate as evaluate_policy
from .policyset import decide as decide_policyset


def _actions(rule: Dict[str, Any]) -> Tuple[str, ...]:
    acts_raw = rule.get("actions")
    if not isinstance(acts_raw, Iterable):
        return tuple()
    acts = [a for a in acts_raw if isinstance(a, str)]
    return tuple(acts)


def _resource_types(rule: Dict[str, Any]) -> Tuple[str | None, ...]:
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
        out: List[str | None] = []
        for x in t:
            if isinstance(x, str):
                out.append(None if x == "*" else x)
        return tuple(out) if out else (None,)
    return (None,)


def _has_id(rule: Dict[str, Any]) -> bool:
    r = rule.get("resource") or {}
    return r.get("id") is not None


def _has_attrs(rule: Dict[str, Any]) -> bool:
    r = rule.get("resource") or {}
    attrs = (
        r.get("attrs") or r.get("attributes") or {}
    )  # attributes is also accepted for backward compatibility
    return isinstance(attrs, dict) and len(attrs) > 0


def _type_matches(rule_types: Sequence[str | None], res_type: str | None) -> bool:
    if not rule_types:
        return True
    return (res_type in rule_types) or (None in rule_types)


def _categorize(rule: Dict[str, Any], res_type: str | None) -> int | None:
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


def compile(policy: Dict[str, Any]) -> Any:
    """Compile a policy into a fast decision function with prioritized rule ordering.

    Priority within a request: pick the *most specific* non-empty bucket
    (id-specific > attrs-constrained > type-only > wildcard) and evaluate
    only rules from that bucket. For policy *sets*, delegate to policyset.decide.
    """
    # PolicySet: delegate to policyset evaluator (no compilation here)
    if "policies" in policy:
        return lambda env: decide_policyset(policy, env)

    rules = policy.get("rules") or []
    algo = (policy.get("algorithm") or "permit-overrides").lower()

    # Map actions -> rules (stable order). '*' kept separately and appended last.
    by_action: Dict[str, List[Dict[str, Any]]] = {}
    star_rules: List[Dict[str, Any]] = []
    for rule in rules:
        acts = _actions(rule)
        if not acts:
            continue
        if "*" in acts:
            star_rules.append(rule)
        for a in acts:
            if a == "*":
                continue
            by_action.setdefault(a, []).append(rule)

    def decide(env: Dict[str, Any]) -> Dict[str, Any]:
        action_val = env.get("action")
        action: str = str(action_val) if action_val is not None else ""
        res = env.get("resource") or {}
        _rt = res.get("type")
        res_type: str | None = None if _rt is None else str(_rt)

        # Collect action-matched rules, preserving insertion order and de-duplicating
        candidates: List[Dict[str, Any]] = []
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

        # Put candidates into buckets and PICK ONLY the most specific non-empty bucket
        buckets: List[List[Dict[str, Any]]] = [[], [], [], []]
        for r in candidates:
            cat = _categorize(r, res_type)
            if cat is None:
                continue
            buckets[cat].append(r)
        selected: List[Dict[str, Any]] = []
        for i in range(4):
            if buckets[i]:
                selected = buckets[i]
                break

        compiled_policy = {"algorithm": algo, "rules": selected}
        return evaluate_policy(compiled_policy, env)

    return decide


__all__ = ["compile"]
