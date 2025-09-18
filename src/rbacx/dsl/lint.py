from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Tuple

Issue = Dict[str, Any]


def _actions(rule: Dict[str, Any]) -> Tuple[str, ...]:
    """Return normalized action list (only strings)."""
    acts_raw = rule.get("actions")
    if not isinstance(acts_raw, Iterable):
        return tuple()
    acts: List[str] = [a for a in acts_raw if isinstance(a, str)]
    # keep order but drop duplicates while preserving first occurrence
    seen: set[str] = set()
    out: List[str] = []
    for a in acts:
        if a not in seen:
            out.append(a)
            seen.add(a)
    return tuple(out)


def _rtype(rule: Dict[str, Any]) -> Optional[str]:
    """Normalize resource.type into a single comparable string or None."""
    r = rule.get("resource") or {}
    t = r.get("type")
    if t is None:
        return None
    if isinstance(t, list):
        vals = [str(x) for x in t if x is not None]
        return ",".join(sorted(vals)) if vals else None
    return str(t)


def _rid(rule: Dict[str, Any]) -> Optional[str]:
    r = rule.get("resource") or {}
    rid = r.get("id")
    return None if rid is None else str(rid)


def _rattrs(rule: Dict[str, Any]) -> Dict[str, Any]:
    r = rule.get("resource") or {}
    attrs = r.get("attrs") or r.get("attributes") or {}  # canonical key: \"attrs\" (\"attributes\" supported for backward compatibility)
    return attrs if isinstance(attrs, dict) else {}


def _is_broad_resource(rule: Dict[str, Any]) -> bool:
    """Broad if type is missing or '*'."""
    t = _rtype(rule)
    return t is None or t == "*" or (isinstance(t, str) and t.strip() == "")


def _resource_covers(earlier: Dict[str, Any], later: Dict[str, Any]) -> bool:
    er = earlier.get("resource") or {}
    lr = later.get("resource") or {}

    et = er.get("type")
    lt = lr.get("type")
    if et not in (None, "*") and str(et) != str(lt):
        return False

    eid = er.get("id")
    lid = lr.get("id")
    if eid is not None:
        return str(eid) == (None if lid is None else str(lid))

    eattrs = er.get("attrs") or er.get("attributes") or {}
    lattrs = lr.get("attrs") or lr.get("attributes") or {}
    if not isinstance(eattrs, dict) or not isinstance(lattrs, dict):
        return True
    for k, v in eattrs.items():
        if k not in lattrs:
            return False
        if lattrs.get(k) != v:
            return False
    return True


def _first_applicable_unreachable(earlier: Dict[str, Any], later: Dict[str, Any]) -> bool:
    if (earlier.get("effect") or "permit") != (later.get("effect") or "permit"):
        return False
    a_earlier = set(_actions(earlier))
    a_later = set(_actions(later))
    if not a_later.issubset(a_earlier):
        return False
    return _resource_covers(earlier, later)


def analyze_policy(policy: Dict[str, Any], *, require_attrs: Dict[str, List[str]] | None = None) -> List[Issue]:
    """Analyze single policy and return list of issues (dicts with 'code' and fields)."""
    issues: List[Issue] = []

    # config for required attributes per resource type
    req = require_attrs
    if req is None:
        lint_cfg = policy.get("lint") or {}
        req = lint_cfg.get("require_attrs") if isinstance(lint_cfg, dict) else None
    if req is None:
        req = {}

    id_counts: Dict[str, int] = {}
    rid_counts: Dict[Tuple[Optional[str], Optional[str]], int] = {}

    algorithm = str(policy.get("algorithm") or "deny-overrides").lower()
    rules = policy.get("rules") or []
    if not isinstance(rules, list):
        return issues

    # First pass: local validations
    for idx, rule in enumerate(rules):
        rid = rule.get("id")
        if not isinstance(rid, str) or not rid:
            issues.append({"code": "MISSING_ID", "index": idx})
        else:
            id_counts[rid] = id_counts.get(rid, 0) + 1

        acts = _actions(rule)
        if len(acts) == 0:
            issues.append({"code": "EMPTY_ACTIONS", "id": rid, "index": idx})

        if _is_broad_resource(rule):
            issues.append({"code": "BROAD_RESOURCE", "id": rid, "index": idx})

        # Required attributes apply to PERMIT rules only
        rtype = _rtype(rule)
        effect = (rule.get("effect") or "permit").lower()
        if effect == "permit" and rtype and rtype in req:
            attrs = _rattrs(rule)
            missing = [a for a in req[rtype] if a not in attrs]
            if missing:
                issues.append({"code": "REQUIRED_ATTRS", "id": rid, "index": idx, "missing": missing})

        # Duplicate resource id per (type, id)
        r_id = _rid(rule)
        key = (rtype, r_id)
        rid_counts[key] = rid_counts.get(key, 0) + 1

    for rule_id, c in id_counts.items():
        if c > 1:
            issues.append({"code": "DUPLICATE_ID", "id": rule_id})

    for key, c in rid_counts.items():
        rtype, resid = key
        if resid is not None and c > 1:
            issues.append({"code": "DUPLICATE_RESOURCE_ID", "resource_type": rtype, "resource_id": resid})

    # Second pass: cross-rule relationships
    if algorithm == "first-applicable":
        for later_idx in range(1, len(rules)):
            later = rules[later_idx]
            for earlier_idx in range(0, later_idx):
                earlier = rules[earlier_idx]
                if _first_applicable_unreachable(earlier, later):
                    issues.append(
                        {
                            "code": "POTENTIALLY_UNREACHABLE",
                            "later_id": later.get("id"),
                            "earlier_id": earlier.get("id"),
                            "later_index": later_idx,
                            "earlier_index": earlier_idx,
                        }
                    )
                    break

    # Deny overrides overlaps
    if algorithm == "deny-overrides":
        for earlier_idx, earlier in enumerate(rules):
            if (earlier.get("effect") or "permit") != "deny":
                continue
            for later_idx in range(earlier_idx + 1, len(rules)):
                later = rules[later_idx]
                if _resource_covers(earlier, later):
                    if set(_actions(earlier)) & set(_actions(later)):
                        issues.append(
                            {
                                "code": "OVERLAPPED_BY_DENY",
                                "later_id": later.get("id"),
                                "earlier_id": earlier.get("id"),
                                "later_index": later_idx,
                                "earlier_index": earlier_idx,
                            }
                        )
                        break

    return issues


def analyze_policyset(policyset: Dict[str, Any], *, require_attrs: Dict[str, List[str]] | None = None) -> List[Issue]:
    """Analyze a policy set; returns flat list with 'policy_index' for each issue."""
    issues: List[Issue] = []
    for pidx, pol in enumerate(policyset.get("policies") or []):
        sub = analyze_policy(pol, require_attrs=require_attrs)
        for it in sub:
            it = dict(it)
            it["policy_index"] = pidx
            issues.append(it)
    return issues


__all__ = ["analyze_policy", "analyze_policyset"]
