from rbacx.core.policy import evaluate


def _env(action="read", res_id="1", attrs=None):
    return {
        "action": action,
        "resource": {"type": "doc", "id": res_id, "attrs": attrs or {}},
        "subject": {"id": "u", "roles": [], "attrs": {}},
        "context": {},
    }


def test_rules_not_list_and_empty_rules():
    out = evaluate({"rules": {}}, _env())
    assert out["decision"] == "deny" and out["reason"] in ("no_match", "invalid_rules")
    out2 = evaluate({"rules": []}, _env())
    assert out2["decision"] == "deny" and out2["reason"] == "no_match"
