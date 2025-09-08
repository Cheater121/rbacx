from __future__ import annotations

from typing import Any, Dict, Optional

from .policy import evaluate as evaluate_policy


def _decide_single(obj: Dict[str, Any], env: Dict[str, Any]) -> Dict[str, Any]:
    """Decide for a single policy or nested policy set."""
    if "policies" in obj:
        return decide(obj, env)
    return evaluate_policy(obj, env)


def _is_applicable(result: Dict[str, Any]) -> bool:
    """A policy is applicable only if a concrete rule matched (has rule_id)."""
    rid = result.get("last_rule_id") or result.get("rule_id")
    return isinstance(rid, str) and rid != ""


def decide(policyset: Dict[str, Any], env: Dict[str, Any]) -> Dict[str, Any]:
    """Evaluate a policy set with combining algorithm over its child policies."""
    algo = (policyset.get("algorithm") or "deny-overrides").lower()
    policies = policyset.get("policies") or []
    if not isinstance(policies, list):
        return {"decision": "deny", "reason": "no_match", "rule_id": None, "last_rule_id": None, "policy_id": None, "obligations": []}

    any_permit: bool = False
    any_deny: bool = False

    first_applicable_result: Optional[Dict[str, Any]] = None
    first_applicable_pid: Optional[str] = None

    permit_result: Optional[Dict[str, Any]] = None
    permit_pid: Optional[str] = None

    deny_result: Optional[Dict[str, Any]] = None
    deny_pid: Optional[str] = None

    last_rule_id: Optional[str] = None

    for pol in policies:
        pid = pol.get("id")
        res = _decide_single(pol, env)

        rid = res.get("last_rule_id") or res.get("rule_id")
        if isinstance(rid, str) and rid:
            last_rule_id = rid

        if not _is_applicable(res):
            continue

        decision = str(res.get("decision") or "")
        if algo == "first-applicable":
            first_applicable_result = res
            first_applicable_pid = pid
            break

        if decision == "deny":
            any_deny = True
            if deny_result is None:
                deny_result = res
                deny_pid = pid
            if algo == "deny-overrides":
                break
        elif decision == "permit":
            any_permit = True
            if permit_result is None:
                permit_result = res
                permit_pid = pid
            if algo == "permit-overrides":
                break
        else:
            continue

    if algo == "first-applicable":
        if first_applicable_result is not None:
            out = dict(first_applicable_result)
            out["policy_id"] = first_applicable_pid
            return out
        return {"decision": "deny", "reason": "no_match", "rule_id": None, "last_rule_id": last_rule_id, "policy_id": None, "obligations": []}

    if algo == "deny-overrides":
        if any_deny and deny_result is not None:
            return {
                "decision": "deny",
                "reason": "explicit_deny",
                "rule_id": deny_result.get("last_rule_id") or deny_result.get("rule_id"),
                "last_rule_id": deny_result.get("last_rule_id") or deny_result.get("rule_id"),
                "policy_id": deny_pid,
                "obligations": list(deny_result.get("obligations") or []),
            }
        if any_permit and permit_result is not None:
            out = dict(permit_result)
            out["policy_id"] = permit_pid
            out["reason"] = out.get("reason") or "matched"
            return out
        return {"decision": "deny", "reason": "no_match", "rule_id": None, "last_rule_id": last_rule_id, "policy_id": None, "obligations": []}

    # permit-overrides
    if any_permit and permit_result is not None:
        out = dict(permit_result)
        out["policy_id"] = permit_pid
        out["reason"] = out.get("reason") or "matched"
        return out
    if any_deny and deny_result is not None:
        return {
            "decision": "deny",
            "reason": "explicit_deny",
            "rule_id": deny_result.get("last_rule_id") or deny_result.get("rule_id"),
            "last_rule_id": deny_result.get("last_rule_id") or deny_result.get("rule_id"),
            "policy_id": deny_pid,
            "obligations": list(deny_result.get("obligations") or []),
        }

    return {"decision": "deny", "reason": "no_match", "rule_id": None, "last_rule_id": last_rule_id, "policy_id": None, "obligations": []}


__all__ = ["decide"]
