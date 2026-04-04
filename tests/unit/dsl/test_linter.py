from rbacx.dsl.lint import analyze_policy


def test_missing_and_duplicate_ids_and_empty_actions():
    pol = {
        "algorithm": "first-applicable",
        "rules": [
            {"id": "a", "effect": "permit", "actions": ["read"], "resource": {"type": "doc"}},
            {"effect": "permit", "actions": ["read"], "resource": {"type": "doc"}},  # missing id
            {
                "id": "a",
                "effect": "permit",
                "actions": [],
                "resource": {"type": "*"},
            },  # duplicate id, empty actions, broad resource
            {
                "id": "b",
                "effect": "permit",
                "actions": ["read"],
                "resource": {"type": "doc"},
            },  # same shape as first -> potentially unreachable
        ],
    }
    issues = analyze_policy(pol)
    codes = {i["code"] for i in issues}
    assert "MISSING_ID" in codes
    assert "DUPLICATE_ID" in codes
    assert "EMPTY_ACTIONS" in codes
    assert "BROAD_RESOURCE" in codes
    assert "POTENTIALLY_UNREACHABLE" in codes


# ---------------------------------------------------------------------------
# _condition_references_subject_roles — coverage for all branches
# ---------------------------------------------------------------------------

from rbacx.dsl.lint import _condition_references_subject_roles


def test_condition_references_subject_roles_non_dict():
    """Non-dict input returns False immediately (line 101)."""
    assert _condition_references_subject_roles(None) is False
    assert _condition_references_subject_roles("subject.roles") is False
    assert _condition_references_subject_roles(42) is False
    assert _condition_references_subject_roles([]) is False


def test_condition_references_subject_roles_operands_not_list():
    """Operator present but its value is not a list — skipped (transition 105→102)."""
    # hasAny with a non-list value
    assert _condition_references_subject_roles({"hasAny": "not-a-list"}) is False
    assert _condition_references_subject_roles({"==": {"attr": "subject.roles"}}) is False


def test_condition_references_subject_roles_and_value_not_list():
    """'and' present but its value is not a list — skipped (transition 112→109)."""
    assert _condition_references_subject_roles({"and": "not-a-list"}) is False
    assert _condition_references_subject_roles({"or": 42}) is False


def test_condition_references_subject_roles_and_no_match():
    """'and' list present but no element references subject.roles (transition 113→109)."""
    cond = {
        "and": [
            {"==": [{"attr": "resource.attrs.type"}, "doc"]},
            {"==": [{"attr": "subject.id"}, "u1"]},
        ]
    }
    assert _condition_references_subject_roles(cond) is False


def test_condition_references_subject_roles_hasany_match():
    """hasAny with subject.roles in operands returns True."""
    cond = {"hasAny": [{"attr": "subject.roles"}, ["admin"]]}
    assert _condition_references_subject_roles(cond) is True


def test_condition_references_subject_roles_not_subtree():
    """Recurses into 'not' subtree."""
    cond = {"not": {"hasAny": [{"attr": "subject.roles"}, ["viewer"]]}}
    assert _condition_references_subject_roles(cond) is True
    assert _condition_references_subject_roles({"not": {"==": [1, 1]}}) is False
