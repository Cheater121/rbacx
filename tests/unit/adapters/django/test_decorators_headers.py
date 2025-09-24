# Minimal stub that mimics Django's HttpResponseForbidden enough for our checks.
class StubForbiddenResponse:
    def __init__(self, content="Forbidden", status=403):
        # Django stores bytes in .content; emulate that
        self.content = content.encode() if isinstance(content, str) else content
        self.status_code = status
        self._headers = {}

    # Header mapping API compatible with Django Response
    def __setitem__(self, key, value):  # resp["X-..."] = "..."
        self._headers[key] = value

    def __contains__(self, key):  # "X-..." in resp
        return key in self._headers

    def __getitem__(self, key):  # resp["X-..."]
        return self._headers[key]


def _wrap(require_access, guard, *, audit=False, add_headers=True):
    # Pure unit: no Django imports. The decorator only calls our view or returns a stubbed response.
    def build_env(_req):
        return ("u", "a", "r", {"c": 1})

    def view_ok(_request, *args, **kwargs):
        # Any python object is fine; decorator must pass it through on allow/audit
        return {"ok": True}

    return require_access(
        guard=guard,
        build_env=build_env,
        add_headers=add_headers,
        audit=audit,
    )(view_ok)


def test_fail_closed_no_guard_audit_false_returns_forbidden(monkeypatch):
    """
    Covers 41-45: no guard + audit=False -> fail-closed -> HttpResponseForbidden("Forbidden").
    """
    from rbacx.adapters.django import decorators as dj_mod

    # Patch the symbol the module uses to construct forbidden responses
    monkeypatch.setattr(dj_mod, "HttpResponseForbidden", StubForbiddenResponse, raising=True)

    guard = None
    wrapped = _wrap(dj_mod.require_access, guard, audit=False, add_headers=True)

    resp = wrapped(object())  # "request" can be any object for unit scope
    assert isinstance(resp, StubForbiddenResponse)
    assert resp.status_code == 403
    assert b"Forbidden" in resp.content


def test_pass_through_no_guard_audit_true_calls_view(monkeypatch):
    """
    Covers 41-45 (audit branch): no guard + audit=True -> pass-through to view.
    """
    from rbacx.adapters.django import decorators as dj_mod

    # Even if we patch forbidden, it shouldn't be used in this branch
    monkeypatch.setattr(dj_mod, "HttpResponseForbidden", StubForbiddenResponse, raising=True)

    guard = None
    wrapped = _wrap(dj_mod.require_access, guard, audit=True, add_headers=True)

    resp = wrapped(object())
    assert resp == {"ok": True}  # original view return


def test_deny_adds_reason_rule_policy_headers_when_present(monkeypatch):
    """
    Covers 55-62 and 64-65: deny -> create Forbidden + add headers when values are truthy.
    """
    from rbacx.adapters.django import decorators as dj_mod

    monkeypatch.setattr(dj_mod, "HttpResponseForbidden", StubForbiddenResponse, raising=True)

    class Decision:
        def __init__(self, allowed, reason=None, rule_id=None, policy_id=None):
            self.allowed = allowed
            self.reason = reason
            self.rule_id = rule_id
            self.policy_id = policy_id

    class Guard:
        # The decorator calls evaluate_sync if present — provide it explicitly.
        def evaluate_sync(self, *_a, **_k):
            return Decision(
                allowed=False,
                reason="not-allowed-by-policy",
                rule_id="rule-42",
                policy_id="policy-main",
            )

        # Keep async variant too, just in case
        async def evaluate_async(self, *_a, **_k):
            return self.evaluate_sync()

        # And a sync 'evaluate' fallback (some adapters look for it)
        def evaluate(self, *_a, **_k):
            return self.evaluate_sync()

    wrapped = _wrap(dj_mod.require_access, Guard(), audit=False, add_headers=True)
    resp = wrapped(object())

    assert isinstance(resp, StubForbiddenResponse)
    assert resp.status_code == 403
    # Headers must be present when the decision carries values
    assert resp["X-RBACX-Reason"] == "not-allowed-by-policy"
    assert resp["X-RBACX-Rule"] == "rule-42"
    assert resp["X-RBACX-Policy"] == "policy-main"


def test_deny_omits_optional_headers_when_values_falsy(monkeypatch):
    """
    Negative branches for 58->60, 62, 65:
    - No reason -> X-RBACX-Reason absent
    - No rule_id -> X-RBACX-Rule absent
    - No policy_id -> X-RBACX-Policy absent
    """
    from rbacx.adapters.django import decorators as dj_mod

    monkeypatch.setattr(dj_mod, "HttpResponseForbidden", StubForbiddenResponse, raising=True)

    class Decision:
        def __init__(self, allowed, reason=None, rule_id=None, policy_id=None):
            self.allowed = allowed
            self.reason = reason
            self.rule_id = rule_id
            self.policy_id = policy_id

    class Guard:
        def evaluate_sync(self, *_a, **_k):
            return Decision(allowed=False, reason=None, rule_id=None, policy_id=None)

        async def evaluate_async(self, *_a, **_k):
            return self.evaluate_sync()

        def evaluate(self, *_a, **_k):
            return self.evaluate_sync()

    wrapped = _wrap(dj_mod.require_access, Guard(), audit=False, add_headers=True)
    resp = wrapped(object())

    assert resp.status_code == 403
    assert "X-RBACX-Reason" not in resp
    assert "X-RBACX-Rule" not in resp
    assert "X-RBACX-Policy" not in resp
