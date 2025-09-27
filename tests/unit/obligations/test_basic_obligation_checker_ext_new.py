import pytest

from rbacx.core.obligations import BasicObligationChecker
from rbacx.core.model import Context


def _dec(effect, obligations):
    return {"allowed": effect == "permit", "effect": effect, "obligations": obligations}


@pytest.mark.parametrize("ctx_attrs, ok, ch", [
    ({"mfa": True}, True, None),
    ({"mfa": False}, False, "mfa"),
    ({}, False, "mfa"),
])
def test_require_mfa(ctx_attrs, ok, ch):
    dec = _dec("permit", [{"on": "permit", "type": "require_mfa"}])
    res = BasicObligationChecker().check(dec, Context(attrs=ctx_attrs))
    assert res == (ok, ch)


@pytest.mark.parametrize("ctx_level, min_level, ok, ch", [
    (2, 1, True, None),
    (1, 2, False, "step_up"),
    (0, 1, False, "step_up"),
])
def test_require_level(ctx_level, min_level, ok, ch):
    dec = _dec("permit", [{"on": "permit", "type": "require_level", "attrs": {"min": min_level}}])
    res = BasicObligationChecker().check(dec, Context(attrs={"auth_level": ctx_level}))
    assert res == (ok, ch)


@pytest.mark.parametrize("scheme, expect", [
    ("Basic", "http_basic"),
    ("Bearer", "http_bearer"),
    ("Digest", "http_digest"),
    ("Foo", "http_auth"),
    (None, "http_auth"),
])
def test_http_challenge(scheme, expect):
    attrs = {} if scheme is None else {"scheme": scheme}
    dec = _dec("deny", [{"on": "deny", "type": "http_challenge", "attrs": attrs}])
    ok, ch = BasicObligationChecker().check(dec, Context(attrs={}))
    assert (ok, ch) == (False, expect)


def test_require_consent_specific_key():
    dec = _dec("permit", [{"on": "permit", "type": "require_consent", "attrs": {"key": "privacy"}}])
    ok1, ch1 = BasicObligationChecker().check(dec, Context(attrs={"consent": {"privacy": True}}))
    ok2, ch2 = BasicObligationChecker().check(dec, Context(attrs={"consent": {"privacy": False}}))
    assert (ok1, ch1) == (True, None)
    assert (ok2, ch2) == (False, "consent")


def test_require_terms_accept():
    dec = _dec("permit", [{"on": "permit", "type": "require_terms_accept"}])
    ok1, ch1 = BasicObligationChecker().check(dec, Context(attrs={"tos_accepted": True}))
    ok2, ch2 = BasicObligationChecker().check(dec, Context(attrs={"tos_accepted": False}))
    assert (ok1, ch1) == (True, None)
    assert (ok2, ch2) == (False, "tos")


def test_require_captcha():
    dec = _dec("permit", [{"on": "permit", "type": "require_captcha"}])
    ok1, ch1 = BasicObligationChecker().check(dec, Context(attrs={"captcha_passed": True}))
    ok2, ch2 = BasicObligationChecker().check(dec, Context(attrs={"captcha_passed": False}))
    assert (ok1, ch1) == (True, None)
    assert (ok2, ch2) == (False, "captcha")


@pytest.mark.parametrize("age, max_age, ok, ch", [
    (10, 300, True, None),
    (400, 300, False, "reauth"),
])
def test_require_reauth(age, max_age, ok, ch):
    dec = _dec("permit", [{"on": "permit", "type": "require_reauth", "attrs": {"max_age": max_age}}])
    res = BasicObligationChecker().check(dec, Context(attrs={"reauth_age_seconds": age}))
    assert res == (ok, ch)


def test_require_age_verified():
    dec = _dec("permit", [{"on": "permit", "type": "require_age_verified"}])
    ok1, ch1 = BasicObligationChecker().check(dec, Context(attrs={"age_verified": True}))
    ok2, ch2 = BasicObligationChecker().check(dec, Context(attrs={"age_verified": False}))
    assert (ok1, ch1) == (True, None)
    assert (ok2, ch2) == (False, "age_verification")


def test_ignores_obligations_for_other_effects():
    # Obligation targets 'deny', but effect is 'permit' -> ignored
    dec = _dec("permit", [{"on": "deny", "type": "require_mfa"}])
    ok, ch = BasicObligationChecker().check(dec, Context(attrs={}))
    assert (ok, ch) == (True, None)


def test_unknown_type_is_ignored():
    dec = _dec("permit", [{"on": "permit", "type": "unknown_kind"}])
    ok, ch = BasicObligationChecker().check(dec, Context(attrs={}))
    assert (ok, ch) == (True, None)
