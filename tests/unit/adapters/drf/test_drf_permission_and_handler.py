import pytest


# Minimal stub Response with header mapping semantics like DRF/Django responses
class StubResponse:
    def __init__(self, data=None, status=403):
        self.data = data
        self.status_code = status
        self._headers = {}

    def __setitem__(self, key, value):
        self._headers[key] = value

    def __getitem__(self, key):
        return self._headers[key]

    def get(self, key, default=None):
        return self._headers.get(key, default)


def test_permission_allows_true_path_returns_true():
    """
    Covers lines 42-46 (last line): decision.allowed=True -> has_permission returns True.
    """
    from rbacx.adapters import drf as rbacx_drf

    class Decision:
        def __init__(self, allowed, reason=None, rule_id=None, policy_id=None):
            self.allowed = allowed
            self.reason = reason
            self.rule_id = rule_id
            self.policy_id = policy_id

    class Guard:
        def evaluate_sync(self, *_args, **_kwargs):
            return Decision(allowed=True)

    def build_env(_request):
        return ("sub", "act", "res", {"ctx": True})

    PermissionClass = rbacx_drf.make_permission(
        guard=Guard(), build_env=build_env, add_headers=True
    )
    perm = PermissionClass()

    fake_request = object()
    assert perm.has_permission(fake_request, view=None) is True
    assert not hasattr(fake_request, "_rbacx_denied_headers")


def test_permission_denied_stashes_all_headers():
    """
    Covers positive transitions of 48-59:
    reason/rule_id/policy_id are all truthy -> all headers are stashed.
    """
    from rbacx.adapters import drf as rbacx_drf

    class Decision:
        def __init__(self, allowed, reason=None, rule_id=None, policy_id=None):
            self.allowed = allowed
            self.reason = reason
            self.rule_id = rule_id
            self.policy_id = policy_id

    class Guard:
        def evaluate_sync(self, *_args, **_kwargs):
            return Decision(
                allowed=False,
                reason="not-allowed-by-policy",
                rule_id="rule-42",
                policy_id="policy-main",
            )

    def build_env(_request):
        return ("sub", "act", "res", {"ctx": True})

    PermissionClass = rbacx_drf.make_permission(
        guard=Guard(), build_env=build_env, add_headers=True
    )
    perm = PermissionClass()

    class Req: ...

    req = Req()

    assert perm.has_permission(req, view=None) is False
    stashed = req._rbacx_denied_headers
    assert stashed["X-RBACX-Reason"] == "not-allowed-by-policy"
    assert stashed["X-RBACX-Rule"] == "rule-42"
    assert stashed["X-RBACX-Policy"] == "policy-main"


def test_permission_denied_add_headers_false_does_not_stash():
    """
    Ensures add_headers gate is respected (exercises a different transition than above).
    """
    from rbacx.adapters import drf as rbacx_drf

    class Decision:
        def __init__(self, allowed, reason=None, rule_id=None, policy_id=None):
            self.allowed = allowed
            self.reason = reason
            self.rule_id = rule_id
            self.policy_id = policy_id

    class Guard:
        def evaluate_sync(self, *_args, **_kwargs):
            return Decision(allowed=False, reason="r", rule_id="x", policy_id="y")

    def build_env(_request):
        return ("sub", "act", "res", {"ctx": True})

    PermissionClass = rbacx_drf.make_permission(
        guard=Guard(), build_env=build_env, add_headers=False
    )
    perm = PermissionClass()

    class Req: ...

    req = Req()

    assert perm.has_permission(req, view=None) is False
    assert not hasattr(req, "_rbacx_denied_headers")


@pytest.mark.parametrize(
    "reason, rule_id, policy_id, expected_headers",
    [
        ("reason-here", None, None, {"X-RBACX-Reason": "reason-here"}),
        (None, "rule-777", None, {"X-RBACX-Rule": "rule-777"}),
        (None, None, "policy-abc", {"X-RBACX-Policy": "policy-abc"}),
    ],
)
def test_permission_denied_partial_headers_variants(reason, rule_id, policy_id, expected_headers):
    """
    Drives each small `if` independently to exercise both True/False edges:
    - only one of reason/rule_id/policy_id is truthy at a time.
    """
    from rbacx.adapters import drf as rbacx_drf

    class Decision:
        def __init__(self, allowed, reason=None, rule_id=None, policy_id=None):
            self.allowed = allowed
            self.reason = reason
            self.rule_id = rule_id
            self.policy_id = policy_id

    class Guard:
        def evaluate_sync(self, *_args, **_kwargs):
            return Decision(allowed=False, reason=reason, rule_id=rule_id, policy_id=policy_id)

    def build_env(_request):
        return ("sub", "act", "res", {"ctx": True})

    PermissionClass = rbacx_drf.make_permission(
        guard=Guard(), build_env=build_env, add_headers=True
    )
    perm = PermissionClass()

    class Req: ...

    req = Req()
    assert perm.has_permission(req, view=None) is False
    stashed = getattr(req, "_rbacx_denied_headers", {})
    assert stashed == expected_headers


def test_exception_handler_returns_none_when_base_returns_none(monkeypatch):
    """
    Covers 79->88: underlying handler returns None -> our handler returns None untouched.
    """
    from rbacx.adapters import drf as rbacx_drf

    def fake_base(exc, context):
        return None

    monkeypatch.setattr(rbacx_drf, "_drf_exception_handler", fake_base, raising=True)
    assert rbacx_drf.rbacx_exception_handler(RuntimeError("x"), {"request": object()}) is None


def test_exception_handler_with_response_but_no_headers(monkeypatch):
    """
    Covers 84->88: base returns Response but there are no _rbacx_denied_headers -> no headers added.
    """
    from rbacx.adapters import drf as rbacx_drf

    def fake_base(exc, context):
        return StubResponse({"detail": "err"}, status=400)

    monkeypatch.setattr(rbacx_drf, "_drf_exception_handler", fake_base, raising=True)

    class Req: ...

    resp = rbacx_drf.rbacx_exception_handler(ValueError("bad"), {"request": Req()})
    assert resp.status_code == 400
    assert resp.get("X-RBACX-Reason") is None
    assert resp.get("X-RBACX-Rule") is None
    assert resp.get("X-RBACX-Policy") is None


def test_exception_handler_copies_all_headers_loop(monkeypatch):
    """
    Covers lines 85-87 explicitly: iterate over multiple headers and assign each one.
    """
    from rbacx.adapters import drf as rbacx_drf

    # Base handler returns a Response-like object
    class LoggingResponse(StubResponse):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            self.assigned = []

        def __setitem__(self, key, value):
            self.assigned.append((key, value))
            super().__setitem__(key, value)

    def fake_base(exc, context):
        return LoggingResponse({"detail": "forbidden"}, status=403)

    monkeypatch.setattr(rbacx_drf, "_drf_exception_handler", fake_base, raising=True)

    class Req:
        # Three headers to ensure the 'for k,v in hdrs.items()' loop runs multiple times
        _rbacx_denied_headers = {
            "X-RBACX-Reason": "denied",
            "X-RBACX-Rule": "r-1",
            "X-RBACX-Policy": "p-1",
        }

    resp = rbacx_drf.rbacx_exception_handler(Exception("boom"), {"request": Req()})
    assert resp.status_code == 403
    # All headers must have been assigned via loop
    assert resp["X-RBACX-Reason"] == "denied"
    assert resp["X-RBACX-Rule"] == "r-1"
    assert resp["X-RBACX-Policy"] == "p-1"
    # And we really iterated 3 times
    assert len(resp.assigned) == 3
