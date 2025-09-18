from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence

Effect = str  # "permit" | "deny"


class ConditionTypeError(Exception):
    """Raised when a condition compares incompatible types."""


# ------------------------------- helpers ---------------------------------


def match_actions(rule: Dict[str, Any], action: str) -> bool:
    acts_raw = rule.get("actions")
    if not isinstance(acts_raw, Iterable):
        return False
    acts = [a for a in acts_raw if isinstance(a, str)]
    return action in acts or "*" in acts


def match_resource(rdef: Dict[str, Any], resource: Dict[str, Any]) -> bool:
    if not isinstance(rdef, dict):
        return False
    if not rdef:
        return True

    r_type = rdef.get("type")
    r_id = rdef.get("id")
    r_attrs = rdef.get("attrs") or rdef.get("attributes") or {}  # canonical key: \"attrs\" (\"attributes\" supported for backward compatibility)

    res_type = resource.get("type")
    res_id = resource.get("id")
    res_attrs = resource.get("attrs") or resource.get("attributes") or {}

    # type check
    if r_type is not None:
        allowed: Sequence[str]
        if isinstance(r_type, str):
            allowed = [r_type]
        elif isinstance(r_type, list):
            allowed = [str(x) for x in r_type]
        else:
            allowed = [str(r_type)]
        if "*" not in allowed:
            if res_type is None or str(res_type) not in set(allowed):
                return False

    # id check
    if r_id is not None:
        if res_id is None or str(res_id) != str(r_id):
            return False

    # attributes shallow equality / containment
    if isinstance(r_attrs, dict):
        if not isinstance(res_attrs, dict):
            return False
        for k, v in r_attrs.items():
            if k not in res_attrs:
                return False
            rv = res_attrs.get(k)
            if isinstance(v, list):
                # treat as "one-of"
                if str(rv) not in {str(x) for x in v}:
                    return False
            else:
                if str(rv) != str(v):
                    return False
    return True


def resolve(token: Any, env: Dict[str, Any]) -> Any:
    """Resolve a token; supports {"attr": "a.b.c"} lookups in env."""
    if isinstance(token, dict) and "attr" in token:
        path = str(token["attr"]).split(".")
        cur: Any = env
        for p in path:
            if isinstance(cur, dict):
                cur = cur.get(p)
            else:
                cur = getattr(cur, p, None)
        return cur
    return token


def _ensure_numeric_strict(a: Any, b: Any) -> tuple[float, float]:
    """Ensure both values are numeric (int/float). No string coercion."""
    if isinstance(a, bool) or isinstance(b, bool):
        # bool is subclass of int; exclude explicitly for policy semantics
        raise ConditionTypeError("condition_type_mismatch")
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return float(a), float(b)
    raise ConditionTypeError("condition_type_mismatch")


def _ensure_str(a: Any, b: Any) -> tuple[str, str]:
    if not isinstance(a, str) or not isinstance(b, str):
        raise ConditionTypeError("condition_type_mismatch")
    return a, b


def _parse_dt(x: Any) -> datetime:
    """Parse to timezone-aware datetime (UTC). Accepts datetime/epoch/ISO-8601 string."""
    if isinstance(x, datetime):
        return x if x.tzinfo is not None else x.replace(tzinfo=timezone.utc)
    if isinstance(x, (int, float)):
        return datetime.fromtimestamp(float(x), tz=timezone.utc)
    if isinstance(x, str):
        try:
            dt = datetime.fromisoformat(x.replace("Z", "+00:00"))
        except Exception as e:  # noqa: BLE001
            raise ConditionTypeError("condition_type_mismatch") from e
        return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)
    raise ConditionTypeError("condition_type_mismatch")


def _as_collection(x: Any) -> Sequence[Any]:
    if isinstance(x, (list, tuple, set, frozenset)):
        return list(x)
    raise ConditionTypeError("condition_type_mismatch")


# ------------------------------- conditions -------------------------------


def eval_condition(cond: Any, env: Dict[str, Any]) -> bool:
    """Evaluate condition dict safely. On type mismatches, raise ConditionTypeError."""
    if not isinstance(cond, dict):
        return bool(cond)

    if "==" in cond:
        a, b = cond["=="]
        return resolve(a, env) == resolve(b, env)
    if "!=" in cond:
        a, b = cond["!="]
        return resolve(a, env) != resolve(b, env)

    if ">" in cond:
        a, b = cond[">"]
        n1, n2 = _ensure_numeric_strict(resolve(a, env), resolve(b, env))
        return n1 > n2
    if "<" in cond:
        a, b = cond["<"]
        n1, n2 = _ensure_numeric_strict(resolve(a, env), resolve(b, env))
        return n1 < n2
    if ">=" in cond:
        a, b = cond[">="]
        n1, n2 = _ensure_numeric_strict(resolve(a, env), resolve(b, env))
        return n1 >= n2
    if "<=" in cond:
        a, b = cond["<="]
        n1, n2 = _ensure_numeric_strict(resolve(a, env), resolve(b, env))
        return n1 <= n2

    if "contains" in cond:
        a, b = cond["contains"]
        x1, x2 = resolve(a, env), resolve(b, env)
        if isinstance(x1, (list, tuple, set, frozenset)):
            return x2 in x1
        if isinstance(x1, str) and isinstance(x2, str):
            return x2 in x1
        raise ConditionTypeError("condition_type_mismatch")

    if "in" in cond:
        a, b = cond["in"]
        x1, x2 = resolve(a, env), resolve(b, env)
        # collections vs collections → overlap; otherwise standard membership
        if isinstance(x1, (list, tuple, set, frozenset)) and isinstance(x2, (list, tuple, set, frozenset)):
            return any(val in x1 for val in x2)
        if isinstance(x2, (list, tuple, set, frozenset)):
            return x1 in x2
        if isinstance(x1, (list, tuple, set, frozenset)):
            return x2 in x1
        if isinstance(x1, str) and isinstance(x2, str):
            return x1 in x2
        raise ConditionTypeError("condition_type_mismatch")

    if "hasAll" in cond:
        a, b = cond["hasAll"]
        col = _as_collection(resolve(a, env))
        needed = _as_collection(resolve(b, env))
        return all(x in col for x in needed)

    if "hasAny" in cond:
        a, b = cond["hasAny"]
        col = _as_collection(resolve(a, env))
        options = _as_collection(resolve(b, env))
        return any(x in col for x in options)

    if "startsWith" in cond:
        a, b = cond["startsWith"]
        s1, s2 = _ensure_str(resolve(a, env), resolve(b, env))
        return s1.startswith(s2)

    if "endsWith" in cond:
        a, b = cond["endsWith"]
        s1, s2 = _ensure_str(resolve(a, env), resolve(b, env))
        return s1.endswith(s2)

    if "before" in cond:
        a, b = cond["before"]
        d1 = _parse_dt(resolve(a, env))
        d2 = _parse_dt(resolve(b, env))
        return d1 < d2

    if "after" in cond:
        a, b = cond["after"]
        d1 = _parse_dt(resolve(a, env))
        d2 = _parse_dt(resolve(b, env))
        return d1 > d2

    if "between" in cond:
        a, rng = cond["between"]
        the_dt = _parse_dt(resolve(a, env))
        rng_val = resolve(rng, env)
        if isinstance(rng_val, (list, tuple)) and len(rng_val) == 2:
            start = _parse_dt(resolve(rng_val[0], env))
            end = _parse_dt(resolve(rng_val[1], env))
            return start <= the_dt <= end
        raise ConditionTypeError("condition_type_mismatch")

    if "and" in cond:
        subs = cond["and"]
        if not isinstance(subs, Iterable):
            raise ConditionTypeError("condition_type_mismatch")
        return all(eval_condition(c, env) for c in subs)
    if "or" in cond:
        subs = cond["or"]
        if not isinstance(subs, Iterable):
            raise ConditionTypeError("condition_type_mismatch")
        return any(eval_condition(c, env) for c in subs)
    if "not" in cond:
        return not eval_condition(cond["not"], env)

    return False


# ------------------------------- evaluation -------------------------------


def evaluate(
    policy: Dict[str, Any],
    env: Dict[str, Any],
    *,
    algorithm: str | None = None,
) -> Dict[str, Any]:
    # Default algorithm: deny-overrides (conservative)
    algo = (algorithm or policy.get("algorithm") or "deny-overrides").lower()

    decision: Effect = "deny"
    reason = "no_match"
    last_rule_id: Optional[str] = None
    obligations: List[Dict[str, Any]] = []

    any_permit = False
    any_deny = False
    permit_rule_id: Optional[str] = None
    deny_rule_id: Optional[str] = None
    permit_obligations: List[Dict[str, Any]] = []

    rules = policy.get("rules") or []
    if not isinstance(rules, list):
        return {
            "decision": decision,
            "reason": reason,
            "rule_id": last_rule_id,
            "last_rule_id": last_rule_id,
            "obligations": obligations,
        }

    for rule in rules:
        rid = rule.get("id") or ""
        if not match_actions(rule, env.get("action") or ""):
            reason = "action_mismatch"
            continue
        rdef = rule.get("resource") or {}
        if not match_resource(rdef, env.get("resource") or {}):
            reason = "resource_mismatch"
            continue

        cond = rule.get("condition")
        if cond is not None:
            try:
                if not eval_condition(cond, env):
                    reason = "condition_mismatch"
                    continue
            except ConditionTypeError:
                reason = "condition_type_mismatch"
                continue

        effect: Effect = (rule.get("effect") or "permit").lower()
        rule_obl = rule.get("obligations") or []
        last_rule_id = rid

        if algo == "first-applicable":
            decision = effect
            obligations = list(rule_obl) if isinstance(rule_obl, list) else []
            reason = "explicit_deny" if effect == "deny" else "matched"
            break

        if effect == "deny":
            any_deny = True
            deny_rule_id = rid
            if algo == "deny-overrides":
                decision = "deny"
                reason = "explicit_deny"
                obligations = list(rule_obl) if isinstance(rule_obl, list) else []
                break
        else:  # permit
            any_permit = True
            permit_rule_id = rid
            permit_obligations = list(rule_obl) if isinstance(rule_obl, list) else []
            if algo == "permit-overrides":
                decision = "permit"
                reason = "matched"
                obligations = permit_obligations
                break

    # If no break happened — finalize per algorithm
    if algo == "deny-overrides":
        if any_deny:
            decision = "deny"
            reason = "explicit_deny"
            last_rule_id = deny_rule_id
            obligations = []
        elif any_permit:
            decision = "permit"
            reason = "matched"
            last_rule_id = permit_rule_id
            obligations = permit_obligations
        else:
            # keep the most informative reason gathered
            decision = "deny"
            obligations = []
    elif algo == "permit-overrides":
        if any_permit:
            decision = "permit"
            reason = "matched"
            last_rule_id = permit_rule_id
            obligations = permit_obligations
        elif any_deny:
            decision = "deny"
            reason = "explicit_deny"
            last_rule_id = deny_rule_id
            obligations = []
        else:
            decision = "deny"
            obligations = []
    else:  # first-applicable already handled; if no match:
        if last_rule_id is None:
            decision = "deny"
            # keep reason gathered during iteration

    return {
        "decision": decision,
        "reason": reason,
        "rule_id": last_rule_id,
        "last_rule_id": last_rule_id,
        "obligations": obligations,
    }


# Backwards-compatible alias
def decide(policy: Dict[str, Any], env: Dict[str, Any]) -> Dict[str, Any]:
    return evaluate(policy, env)
