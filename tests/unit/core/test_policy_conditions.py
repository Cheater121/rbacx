import pytest

from rbacx.core.policy import ConditionTypeError, _parse_dt, eval_condition, resolve


def test_resolve_attr_path_and_fallbacks():
    env = {"a": {"b": {"c": 42}}, "x": 1}
    assert resolve({"attr": "a.b.c"}, env) == 42
    assert resolve(5, env) == 5  # passthrough for non-dict tokens


def test_parse_dt_supports_epoch_iso_and_tz():
    # epoch (int/float), naive iso becomes UTC
    assert _parse_dt(0).tzinfo is not None
    assert _parse_dt(0.0).tzinfo is not None
    assert _parse_dt("1970-01-01T00:00:00").tzinfo is not None
    # with Z
    assert _parse_dt("1970-01-01T00:00:00Z").tzinfo is not None
    # wrong type -> ConditionTypeError
    with pytest.raises(ConditionTypeError):
        _parse_dt(object())


def test_eval_condition_basic_ops_and_booleans():
    env = {"a": 1, "b": 2, "c": "x", "tags": ["a", "b"], "dt": "1970-01-02T00:00:00Z"}
    assert eval_condition({"==": [{"attr": "a"}, 1]}, env) is True
    assert eval_condition({"!=": [{"attr": "a"}, 2]}, env) is True
    assert eval_condition({"in": [{"attr": "c"}, ["x", "y"]]}, env) is True
    assert eval_condition({"and": [True, {"==": [{"attr": "b"}, 2]}]}, env) is True
    assert eval_condition({"or": [False, {"==": [{"attr": "b"}, 2]}]}, env) is True
    assert eval_condition({"not": {"==": [{"attr": "b"}, 3]}}, env) is True
    # between (datetime coercion both sides)
    assert (
        eval_condition(
            {"between": [{"attr": "dt"}, ["1969-12-31T00:00:00Z", "1971-01-01T00:00:00Z"]]}, env
        )
        is True
    )


def test_eval_condition_type_errors():
    env = {"a": 1}
    with pytest.raises(ConditionTypeError):
        eval_condition({"in": [{"attr": "a"}, 123]}, env)  # rhs must be collection
    with pytest.raises(ConditionTypeError):
        eval_condition({"between": [{"attr": "a"}, [1]]}, env)  # malformed range
