import inspect

import pytest


# Minimal stub mirroring Litestar's PermissionDeniedException constructor
class StubPermissionDeniedException(Exception):
    def __init__(self, *, detail: str = "", headers: dict | None = None):
        super().__init__(detail)
        self.detail = detail
        self.headers = headers


def _resolve_guard_factory(mod):
    """
    Find a factory in rbacx.adapters.litestar_guard that returns an async guard dependency.
    The factory must accept keyword args: guard, build_env, add_headers, audit.
    """

    def try_candidate(fn):
        try:
            dep = fn(
                guard=object(),
                build_env=lambda c: ("s", "a", "r", {"ctx": True}),
                add_headers=True,
                audit=False,
            )
        except TypeError:
            return None
        return dep if inspect.iscoroutinefunction(dep) else None

    for name in ("make_guard", "require_access", "guard_dependency", "guard"):
        if hasattr(mod, name) and callable(getattr(mod, name)):
            dep = try_candidate(getattr(mod, name))
            if dep:
                return getattr(mod, name)

    for _, obj in inspect.getmembers(mod, callable):
        dep = try_candidate(obj)
        if dep:
            return obj

    pytest.skip("No suitable guard factory exported by rbacx.adapters.litestar_guard")


@pytest.mark.asyncio
async def test_guard_allows_when_decision_allowed_true(monkeypatch):
    """
    Covers: early return when decision.allowed is True.
    """
    from rbacx.adapters import litestar_guard as mod

    monkeypatch.setattr(
        mod, "PermissionDeniedException", StubPermissionDeniedException, raising=True
    )
    factory = _resolve_guard_factory(mod)

    class Decision:
        def __init__(self, allowed, reason=None, rule_id=None, policy_id=None):
            self.allowed = allowed
            self.reason = reason
            self.rule_id = rule_id
            self.policy_id = policy_id

    class Guard:
        async def evaluate_async(self, *_a, **_k):
            return Decision(allowed=True, reason="r", rule_id="id", policy_id="pid")

    def build_env(conn):
        assert conn is connection
        return ("sub", "act", "res", {"ok": 1})

    dependency = factory(guard=Guard(), build_env=build_env, add_headers=True, audit=False)

    connection = object()

    async def dummy_handler(*_a, **_k):  # Litestar passes the route handler as `_handler`
        return None

    # Should NOT raise: early return on allowed=True
    await dependency(connection, _handler=dummy_handler)


@pytest.mark.asyncio
async def test_guard_soft_allow_when_audit_true(monkeypatch):
    """
    Covers: early return when audit=True even if allowed=False.
    """
    from rbacx.adapters import litestar_guard as mod

    monkeypatch.setattr(
        mod, "PermissionDeniedException", StubPermissionDeniedException, raising=True
    )
    factory = _resolve_guard_factory(mod)

    class Decision:
        def __init__(self, allowed, reason=None, rule_id=None, policy_id=None):
            self.allowed = allowed
            self.reason = reason
            self.rule_id = rule_id
            self.policy_id = policy_id

    class Guard:
        async def evaluate_async(self, *_a, **_k):
            return Decision(allowed=False, reason="r", rule_id="id", policy_id="pid")

    dependency = factory(
        guard=Guard(), build_env=lambda c: ("s", "a", "r", {}), add_headers=True, audit=True
    )

    async def dummy_handler(*_a, **_k):
        return None

    # Should NOT raise because audit=True soft-allows
    await dependency(object(), _handler=dummy_handler)


@pytest.mark.asyncio
async def test_guard_deny_adds_reason_rule_policy_headers(monkeypatch):
    """
    Covers: deny path with add_headers=True and all fields set.
    Expect PermissionDeniedException(detail='Forbidden', headers has X-RBACX-Reason/Rule/Policy).
    """
    from rbacx.adapters import litestar_guard as mod

    monkeypatch.setattr(
        mod, "PermissionDeniedException", StubPermissionDeniedException, raising=True
    )
    factory = _resolve_guard_factory(mod)

    class Decision:
        def __init__(self, allowed, reason=None, rule_id=None, policy_id=None):
            self.allowed = allowed
            self.reason = reason
            self.rule_id = rule_id
            self.policy_id = policy_id

    class Guard:
        async def evaluate_async(self, *_a, **_k):
            return Decision(
                allowed=False,
                reason="not-allowed-by-policy",
                rule_id="rule-42",
                policy_id="policy-main",
            )

    dependency = factory(
        guard=Guard(), build_env=lambda c: ("s", "a", "r", {}), add_headers=True, audit=False
    )

    async def dummy_handler(*_a, **_k):
        return None

    with pytest.raises(StubPermissionDeniedException) as ei:
        await dependency(object(), _handler=dummy_handler)

    exc = ei.value
    assert exc.detail == "Forbidden"
    assert exc.headers is not None
    assert exc.headers["X-RBACX-Reason"] == "not-allowed-by-policy"
    assert exc.headers["X-RBACX-Rule"] == "rule-42"
    assert exc.headers["X-RBACX-Policy"] == "policy-main"


@pytest.mark.asyncio
async def test_guard_deny_add_headers_true_but_all_fields_falsy(monkeypatch):
    """
    Covers: deny path with add_headers=True but all fields falsy -> headers=None.
    """
    from rbacx.adapters import litestar_guard as mod

    monkeypatch.setattr(
        mod, "PermissionDeniedException", StubPermissionDeniedException, raising=True
    )
    factory = _resolve_guard_factory(mod)

    class Decision:
        def __init__(self, allowed, reason=None, rule_id=None, policy_id=None):
            self.allowed = allowed
            self.reason = reason
            self.rule_id = rule_id
            self.policy_id = policy_id

    class Guard:
        async def evaluate_async(self, *_a, **_k):
            return Decision(allowed=False, reason=None, rule_id=None, policy_id=None)

    dependency = factory(
        guard=Guard(), build_env=lambda c: ("s", "a", "r", {}), add_headers=True, audit=False
    )

    async def dummy_handler(*_a, **_k):
        return None

    with pytest.raises(StubPermissionDeniedException) as ei:
        await dependency(object(), _handler=dummy_handler)

    exc = ei.value
    assert exc.detail == "Forbidden"
    assert exc.headers is None  # because `headers or None`


@pytest.mark.asyncio
async def test_guard_deny_add_headers_false(monkeypatch):
    """
    Covers: deny path with add_headers=False (even with truthy fields) -> headers=None.
    """
    from rbacx.adapters import litestar_guard as mod

    monkeypatch.setattr(
        mod, "PermissionDeniedException", StubPermissionDeniedException, raising=True
    )
    factory = _resolve_guard_factory(mod)

    class Decision:
        def __init__(self, allowed, reason=None, rule_id=None, policy_id=None):
            self.allowed = allowed
            self.reason = reason
            self.rule_id = rule_id
            self.policy_id = policy_id

    class Guard:
        async def evaluate_async(self, *_a, **_k):
            return Decision(allowed=False, reason="r", rule_id="id", policy_id="pid")

    dependency = factory(
        guard=Guard(), build_env=lambda c: ("s", "a", "r", {}), add_headers=False, audit=False
    )

    async def dummy_handler(*_a, **_k):
        return None

    with pytest.raises(StubPermissionDeniedException) as ei:
        await dependency(object(), _handler=dummy_handler)

    exc = ei.value
    assert exc.detail == "Forbidden"
    assert exc.headers is None
