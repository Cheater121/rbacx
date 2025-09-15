from rbacx.obligations import enforcer as enf


def test_set_by_path_creates_nested_dicts_and_lists():
    obj = {}
    # simple top-level
    enf._set_by_path(obj, "email", "a@b")
    assert obj["email"] == "a@b"
    # nested dict creation
    enf._set_by_path(obj, "profile.name", "John")
    assert obj["profile"]["name"] == "John"
    # list index creation and assignment
    enf._set_by_path(obj, "items[1].title", "Book")
    # items should be a list with index 1 present as dict
    assert isinstance(obj["items"], list)
    assert obj["items"][1]["title"] == "Book"


def test_apply_obligations_mask_and_redact():
    payload = {
        "email": "user@example.com",
        "profile": {"name": "Jane", "phone": "123"},
        "items": [{"title": "A"}, {"title": "B"}],
    }
    obligations = [
        {"type": "mask_fields", "fields": ["email", "items[0].title"], "placeholder": "XXX"},
        {"type": "redact_fields", "fields": ["profile.phone"]},
    ]
    out = enf.apply_obligations(payload, obligations)
    # masked
    assert out["email"] == "XXX"
    assert out["items"][0]["title"] == "XXX"
    # redacted
    assert out["profile"]["phone"] == "[REDACTED]"
    # untouched
    assert out["profile"]["name"] == "Jane"
    assert payload["email"] == "user@example.com"  # original not mutated (function copies)
