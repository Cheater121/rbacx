# -*- coding: utf-8 -*-

from rbacx.obligations.enforcer import _set_by_path, apply_obligations


# ---------- 26->exit: force zero parts by monkeypatching module-level `str` ----------
def test_set_by_path_loop_not_entered_zero_parts(monkeypatch):
    import rbacx.obligations.enforcer as enf

    class FakeStr:
        # Called as str(path) inside the module
        def __call__(self, _):
            class WithSplit:
                def split(self, sep):
                    return []  # empty parts -> for-loop body never executes

            return WithSplit()

    # Shadow built-in `str` only inside the enforcer module
    monkeypatch.setattr(enf, "str", FakeStr(), raising=False)

    obj = {"a": 1}
    enf._set_by_path(obj, "ignored", "ignored")  # no-op due to empty parts
    assert obj == {"a": 1}


# ---------- 24-25 equivalent path: list branch, last segment -> assign and return ----------
def test_set_by_path_list_last_segment_sets_value():
    obj = {}
    _set_by_path(obj, "items[1]", "VAL")
    assert "items" in obj and isinstance(obj["items"], list)
    assert obj["items"][0] == {}  # filled by _ensure_list_size
    assert obj["items"][1] == "VAL"  # assignment at is_last branch


# ---------- 27 / 38: list branch, intermediate segment not a dict -> converted, then continue ----------
def test_set_by_path_list_intermediate_not_dict_fixed():
    obj = {"items": ["not-a-dict"]}
    _set_by_path(
        obj, "items[0].name", "John"
    )  # triggers convert-to-dict + continue to next segment
    assert isinstance(obj["items"][0], dict)
    assert obj["items"][0]["name"] == "John"


# ---------- 34-35: list branch, current container not a dict -> early no-op return ----------
def test_set_by_path_list_container_not_dict_is_noop():
    obj = []  # current container is not a dict; list path should bail out
    _set_by_path(obj, "items[0]", "X")
    assert obj == []


# ---------- extra guard: invalid index in list segment -> early no-op return (covers idx parse except) ----------
def test_set_by_path_invalid_index_is_noop():
    obj = {}
    _set_by_path(obj, "items[bad]", "X")  # bad index => return without changes
    assert obj == {}


# ---------- dict branch, last segment -> assign if current is dict, then return ----------
def test_set_by_path_object_chain_sets_scalar_on_last():
    obj = {}
    _set_by_path(obj, "user.name", "Alice")
    assert obj == {"user": {"name": "Alice"}}


# ---------- dict branch, last segment but current is NON-dict -> no-op + return ----------
def test_set_by_path_last_segment_on_non_dict_is_noop():
    obj = []  # not a dict
    _set_by_path(obj, "field", "X")  # single last segment
    assert obj == []  # unchanged


# ---------- apply_obligations: deep-copy semantics by default (payload unchanged), mask + redact ----------
def test_apply_obligations_masks_and_redacts_deepcopy_default():
    payload = {"user": {"email": "a@b", "name": "Alice"}, "items": [{"price": 10}]}
    obligations = [
        {"type": "mask_fields", "placeholder": "***", "fields": ["user.email", "items[0].price"]},
        {"type": "redact_fields", "fields": ["user.name"]},
    ]
    out = apply_obligations(payload, obligations)

    # out contains masked/redacted values
    assert out["user"]["email"] == "***"
    assert out["user"]["name"] == "[REDACTED]"
    assert out["items"][0]["price"] == "***"

    # original payload is preserved (deep copy semantics)
    assert payload == {"user": {"email": "a@b", "name": "Alice"}, "items": [{"price": 10}]}


# ---------- apply_obligations: in_place=True mutates original and returns the same object ----------
def test_apply_obligations_in_place_true_mutates_original():
    payload = {"user": {"email": "a@b", "name": "Alice"}, "items": [{"price": 10}]}
    obligations = [{"type": "redact_fields", "fields": ["user.name"]}]
    out = apply_obligations(payload, obligations, in_place=True)
    assert out is payload
    assert payload["user"]["name"] == "[REDACTED]"


# ---------- 100: unknown obligation type is ignored (else/continue branch exercised) ----------
def test_apply_obligations_unknown_type_ignored():
    payload = {"data": {"x": 1}}
    obligations = [{"type": "unknown", "fields": ["data.x"]}]
    out = apply_obligations(payload, obligations)
    assert out == payload  # deep copy equal to original (no changes applied)
    assert out is not payload  # ensure it's a copy by default
