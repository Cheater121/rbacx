import pytest

from rbacx.core.obligations import BasicObligationChecker


def _modern(effect: str, obligations=None):
    return {"allowed": effect == "permit", "effect": effect, "obligations": obligations or []}


def test_context_plain_dict_resolution_and_terms_accept_branch():
    """
    Covers context resolution when `context` is a plain dict (no `.attrs`) +
    exercises `require_terms_accept` success and failure.
    """
    chk = BasicObligationChecker()
    dec = _modern("permit", [{"on": "permit", "type": "require_terms_accept"}])

    ok_true, ch_true = chk.check(dec, {"tos_accepted": True})
    assert (ok_true, ch_true) == (True, None)

    ok_false, ch_false = chk.check(dec, {"tos_accepted": False})
    assert (ok_false, ch_false) == (False, "tos")


def test_obligation_with_invalid_on_value_is_ignored_and_baseline_is_returned():
    """
    Covers the `on` filter ignoring invalid values (not in {"permit","deny"}).
    Ensures we hit the final `return baseline_ok, None` for both effects.
    """
    chk = BasicObligationChecker()

    # Effect=permit, invalid `on` -> obligation ignored, baseline True
    dec_permit = _modern("permit", [{"on": "advice", "type": "require_mfa"}])
    ok_p, ch_p = chk.check(dec_permit, {"mfa": False})
    assert (ok_p, ch_p) == (True, None)

    # Effect=deny, invalid `on` -> obligation ignored, baseline False
    dec_deny = _modern("deny", [{"on": "advice", "type": "require_mfa"}])
    ok_d, ch_d = chk.check(dec_deny, {"mfa": False})
    assert (ok_d, ch_d) == (False, None)


def test_require_level_invalid_min_uses_zero_and_fails_when_auth_level_below_zero():
    """
    Covers lines 91-92 in checker: invalid attrs['min'] -> except -> min_level = 0.
    With auth_level = -1 (< 0), checker must fail with 'step_up'.
    """
    chk = BasicObligationChecker()
    dec = _modern("permit", [{"on": "permit", "type": "require_level", "attrs": {"min": "NaN"}}])

    ok, challenge = chk.check(dec, {"auth_level": -1})
    assert (ok, challenge) == (False, "step_up")


def test_require_reauth_invalid_max_age_uses_zero_and_fails_when_age_gt_zero():
    """
    Covers lines 128-130 in checker: invalid attrs['max_age'] -> except -> max_age = 0.
    With reauth_age_seconds = 1 (> 0), checker must fail with 'reauth'.
    """
    chk = BasicObligationChecker()
    dec = _modern("permit", [{"on": "permit", "type": "require_reauth", "attrs": {"max_age": "oops"}}])

    ok, challenge = chk.check(dec, {"reauth_age_seconds": 1})
    assert (ok, challenge) == (False, "reauth")

