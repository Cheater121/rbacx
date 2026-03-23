from datetime import datetime, timezone

import pytest

from rbacx.core.policy import (
    ConditionTypeError,
    _is_strict,
    _parse_dt,
    match_resource,
)


def test__is_strict_fallback_on_bad_env_returns_false():
    class NoGet:  # has no .get -> AttributeError inside _is_strict
        pass

    assert _is_strict(NoGet()) is False


def test_match_resource_type_strict_exact_match_required():
    rdef = {"type": ["doc", "file"]}

    # strict mode is passed via the strict= keyword argument (fixed in 1.8.1:
    # previously the flag was read from the resource dict, which was incorrect)
    assert match_resource(rdef, {"type": "doc"}, strict=True) is True
    assert match_resource(rdef, {"type": 123}, strict=True) is False  # not a str -> must fail


def test_match_resource_id_strict_no_string_coercion():
    rdef = {"id": "1"}

    assert match_resource(rdef, {"id": "1"}, strict=True) is True
    assert match_resource(rdef, {"id": 1}, strict=True) is False  # "1" != 1 in strict mode


def test_match_resource_id_lax_allows_string_coercion_for_backward_compat():
    rdef = {"id": "1"}
    assert match_resource(rdef, {"id": 1}, strict=False) is True


def test_match_resource_attrs_one_of_strict_no_coercion():
    rdef = {"attrs": {"tag": ["1", "2"]}}

    assert match_resource(rdef, {"attrs": {"tag": "1"}}, strict=True) is True
    assert match_resource(rdef, {"attrs": {"tag": 1}}, strict=True) is False  # int vs str


def test_match_resource_attrs_scalar_strict_exact_equality():
    rdef = {"attrs": {"level": 1}}

    assert match_resource(rdef, {"attrs": {"level": 1}}, strict=True) is True
    assert match_resource(rdef, {"attrs": {"level": "1"}}, strict=True) is False


def test__parse_dt_strict_accepts_only_aware_datetime_and_returns_it():
    aware = datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    assert _parse_dt(aware, strict=True) is aware  # should return the same object


def test__parse_dt_strict_rejects_iso_and_epoch():
    with pytest.raises(ConditionTypeError):
        _parse_dt("2024-01-02T03:04:05Z", strict=True)
    with pytest.raises(ConditionTypeError):
        _parse_dt(1704164690, strict=True)


def test_match_resource_type_strict_not_in_allowed_fails():
    rdef = {"type": ["doc", "file"]}
    # strict mode, тип ресурса строка, но не из разрешённых
    resource_not_allowed = {"type": "note", "__strict_types__": True}
    assert match_resource(rdef, resource_not_allowed) is False
