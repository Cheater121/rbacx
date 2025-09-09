import pytest
litestar = pytest.importorskip("litestar")
from litestar import get, Litestar
from litestar.testing import TestClient
from dataclasses import dataclass

from rbacx.adapters.litestar_guard import require as require_guard
from rbacx.core.model import Subject, Action, Resource, Context


@dataclass
class Decision:
    allowed: bool
    reason: str | None = None


class FakeGuard:
    def __init__(self, allowed: bool, reason: str | None = None):
        self._allowed = allowed
        self._reason = reason

    def is_allowed_sync(self, sub, act, res, ctx) -> bool:
        return self._allowed

    def evaluate_sync(self, sub, act, res, ctx) -> Decision:
        return Decision(self._allowed, self._reason)

    def explain_sync(self, sub, act, res, ctx) -> Decision:
        return Decision(self._allowed, self._reason)


def build_env(_conn):
    # Litestar guard обычно передаёт connection; это совместимо
    return Subject(id="u"), Action("read"), Resource(type="doc"), Context(attrs={})


@get("/ok")  # sync handler — warning допустим, это штатно
def ok() -> dict:
    return {"x": 1}


# Для litestar_guard.require ожидается (action, resource_type)
@get("/deny", guards=[require_guard("read", "doc")])
def deny() -> dict:
    return {"y": 2}


def test_litestar_guard_allow_and_deny():
    # allow-сценарий
    app = Litestar(route_handlers=[ok, deny])
    # Положим все распространённые варианты в state:
    app.state.rbacx_guard = FakeGuard(True)
    app.state.rbacx_guard_factory = lambda: FakeGuard(True)
    app.state.rbacx_build_env = build_env
    app.state.rbacx_build_env_factory = lambda: build_env

    with TestClient(app) as client:
        r1 = client.get("/ok")
        assert r1.status_code == 200
        r2 = client.get("/deny")
        assert r2.status_code == 200  # guard пропустил

    # deny-сценарий
    app2 = Litestar(route_handlers=[ok, deny])
    app2.state.rbacx_guard = FakeGuard(False, "nope")
    app2.state.rbacx_guard_factory = lambda: FakeGuard(False, "nope")
    app2.state.rbacx_build_env = build_env
    app2.state.rbacx_build_env_factory = lambda: build_env

    with TestClient(app2) as client:
        r3 = client.get("/deny")
        assert r3.status_code == 403

