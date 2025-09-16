from datetime import datetime, timedelta, timezone

from rbacx.core.policy import evaluate


def _env(action="read", res_id="1", attrs=None, subj=None):
    return {
        "action": action,
        "resource": {"type": "doc", "id": res_id, "attrs": attrs or {}},
        "subject": subj or {"id": "u", "roles": [], "attrs": {}},
        "context": {},
    }


def test_between_inclusive_and_type_mismatch_datetime():
    base = datetime(1970, 1, 2, tzinfo=timezone.utc)
    attrs = {"ts": base.isoformat()}
    # inclusive between -> True
    p = {
        "rules": [
            {
                "id": "r",
                "actions": ["read"],
                "resource": {"type": "doc"},
                "condition": {
                    "between": [
                        {"attr": "resource.attrs.ts"},
                        [
                            (base - timedelta(days=1)).isoformat(),
                            (base + timedelta(days=1)).isoformat(),
                        ],
                    ]
                },
                "effect": "permit",
            }
        ]
    }
    out = evaluate(p, _env(attrs=attrs))
    assert out["decision"] == "permit"
    # type mismatch in bounds triggers ConditionTypeError path inside evaluation of condition -> deny with condition_type_mismatch or condition_mismatch
    p_bad = {
        "rules": [
            {
                "id": "r",
                "actions": ["read"],
                "resource": {"type": "doc"},
                "condition": {"between": [{"attr": "resource.attrs.ts"}, ["not-a-date"]]},
                "effect": "permit",
            }
        ]
    }
    out_bad = evaluate(p_bad, _env(attrs=attrs))
    assert out_bad["decision"] == "deny"
    assert out_bad["reason"] in {"condition_type_mismatch", "condition_mismatch"}


def test_obligations_propagate_on_permit():
    p = {
        "rules": [
            {
                "id": "r",
                "actions": ["read"],
                "resource": {"type": "doc"},
                "obligations": [{"type": "hdr", "key": "X", "value": "1"}],
                "effect": "permit",
            }
        ]
    }
    out = evaluate(p, _env())
    assert out["decision"] == "permit"
    # obligations must be present on success payload
    assert isinstance(out.get("obligations"), list) and out["obligations"]
