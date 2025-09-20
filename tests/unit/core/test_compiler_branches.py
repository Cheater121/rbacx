from rbacx.core import compiler as comp


# ---------- 28–33: _resource_types(list) -> both tuple(out) and (None,) empty-out paths ----------
def test_resource_types_list_variants_tuple_and_empty():
    # List with "*" (wildcard -> None) and a valid string -> tuple(out) branch
    rule1 = {"resource": {"type": ["*", "doc", 123]}}
    assert comp._resource_types(rule1) == (None, "doc")

    # List with no string elements -> out stays empty -> returns (None,) branch
    rule2 = {"resource": {"type": [1, 2, 3]}}
    assert comp._resource_types(rule2) == (None,)


# ---------- 52: _type_matches returns True when rule_types is empty ----------
def test_type_matches_when_rule_types_empty_is_true():
    # Empty sequence must be treated as "no restriction" -> True
    assert comp._type_matches([], "doc") is True
    assert comp._type_matches((), None) is True


# ---------- 115–119 and 120–124: candidate collection dedup + star rules ----------
def test_candidate_collection_dedup_and_star_rules(monkeypatch):
    # Build rules so that:
    # - r1 has actions ["read", "*"] -> appears in by_action["read"] and in star_rules
    # - r2 has action ["read"] -> only in by_action["read"]
    # - r3 has action ["*"] -> only in star_rules
    r1 = {"id": "r1", "actions": ["read", "*"], "resource": {}}
    r2 = {"id": "r2", "actions": ["read"], "resource": {}}
    r3 = {"id": "r3", "actions": ["*"], "resource": {}}

    policy = {"algorithm": "permit-overrides", "rules": [r1, r2, r3]}

    captured = {}

    # Patch evaluate_policy to capture the compiled policy fed by the compiled decide()
    def fake_evaluate_policy(compiled_policy, env):
        captured["rules"] = compiled_policy.get("rules") or []
        # return a minimal decision dict; content doesn't matter for this test
        return {"decision": "deny", "reason": "no_match"}

    monkeypatch.setattr(comp, "evaluate_policy", fake_evaluate_policy, raising=True)

    # Compile and invoke with action="read" so the by_action and star loops both run
    decide = comp.compile(policy)
    out = decide({"action": "read", "resource": {"type": "doc"}})

    # Ensure our stub was called and candidates were deduplicated and ordered:
    # First come rules from by_action["read"] (r1, r2), then star_rules adds r3,
    # but does NOT duplicate r1 (same object id) due to the 'seen' set.
    assert "rules" in captured
    selected = captured["rules"]
    assert [r.get("id") for r in selected] == ["r1", "r2", "r3"]

    # Also ensure decide returned our stub's minimal shape
    assert out["decision"] == "deny"
    assert out["reason"] == "no_match"


# ---------- 115–119: exercise the false branch of "if rid not in seen" (117→115 back-edge) ----------
def test_by_action_loop_skips_duplicate_rule_and_hits_false_branch(monkeypatch):
    from rbacx.core import compiler as comp

    # Same rule object appears twice in policy.rules -> by_action["read"] has duplicates
    r1 = {"id": "r1", "actions": ["read"], "resource": {}}
    policy = {"algorithm": "permit-overrides", "rules": [r1, r1]}  # duplicate SAME object

    captured = {}

    # Capture what compiled decide() passes to evaluate_policy
    def fake_evaluate_policy(compiled_policy, env):
        captured["rules"] = compiled_policy.get("rules") or []
        return {"decision": "deny", "reason": "no_match"}

    monkeypatch.setattr(comp, "evaluate_policy", fake_evaluate_policy, raising=True)

    decide = comp.compile(policy)
    _ = decide({"action": "read", "resource": {"type": "doc"}})

    # Dedup expected: only one r1 remains; second encounter takes the "rid in seen" (False branch)
    assert [r.get("id") for r in captured["rules"]] == ["r1"]
