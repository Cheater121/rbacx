from datetime import datetime, timedelta, timezone

from rbacx.core.policy import eval_condition


def test_contains_on_lists_and_strings():
    env = {"a": [1, 2, 3], "s": "hello world"}
    assert eval_condition({"contains": [{"attr": "a"}, 2]}, env) is True
    assert eval_condition({"contains": [{"attr": "s"}, "world"]}, env) is True
    assert eval_condition({"contains": [{"attr": "a"}, {"attr": "s"}]}, env) is False


def test_in_overlap_and_string_membership():
    env = {"a": [1, 2, 3], "b": [3, 4], "x": "he", "y": "hello"}
    # collections overlap: any of b is in a -> True
    assert eval_condition({"in": [{"attr": "b"}, {"attr": "a"}]}, env) is True
    # collection vs scalar: scalar in collection
    assert eval_condition({"in": [3, {"attr": "a"}]}, env) is True
    # string membership: "he" in "hello"
    assert eval_condition({"in": [{"attr": "x"}, {"attr": "y"}]}, env) is True


def test_hasAll_and_hasAny():
    env = {"tags": ["a", "b", "c"]}
    assert eval_condition({"hasAll": [{"attr": "tags"}, ["a", "b"]]}, env) is True
    assert eval_condition({"hasAny": [{"attr": "tags"}, ["x", "b"]]}, env) is True


def test_starts_ends_before_after_between():
    now = datetime(1970, 1, 2, tzinfo=timezone.utc)
    env = {"s": "prefix_body_suffix", "pref": "pref", "suf": "suffix", "t": now.isoformat()}
    assert eval_condition({"startsWith": [{"attr": "s"}, "prefix"]}, env) is True
    assert eval_condition({"endsWith": [{"attr": "s"}, "suffix"]}, env) is True
    # before/after
    assert (
        eval_condition({"before": [{"attr": "t"}, (now + timedelta(days=1)).isoformat()]}, env)
        is True
    )
    assert (
        eval_condition({"after": [{"attr": "t"}, (now - timedelta(days=1)).isoformat()]}, env)
        is True
    )
    # between inclusive
    assert (
        eval_condition(
            {
                "between": [
                    {"attr": "t"},
                    [(now - timedelta(days=1)).isoformat(), (now + timedelta(days=1)).isoformat()],
                ]
            },
            env,
        )
        is True
    )
