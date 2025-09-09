import pytest
flask = pytest.importorskip("flask")
from flask import Flask, g
from dataclasses import dataclass

from rbacx.adapters.flask import require_access
from rbacx.adapters.flask_guard import require as require_guard
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


def build_env(_request):
    # subject, action, resource, context
    return Subject(id="u"), Action("read"), Resource(type="doc"), Context(attrs={})


def make_app(guard):
    app = Flask(__name__)

    # На случай, если адаптер читает build_env из конфигурации
    app.config["RBACX_BUILD_ENV"] = build_env

    @app.before_request
    def inject():
        g.rbacx_guard = guard

    @app.route("/open")
    def open_ok():
        return "ok"

    @app.route("/guarded")
    @require_access(build_env, "read", "doc")  # ВАЖНО: build_env первым, затем action, затем resource_type
    def guarded():
        return "secret"

    @app.route("/guard-deco")
    @require_guard(build_env, "read", "doc")  # тот же порядок
    def guarded2():
        return "hello"

    return app


def test_flask_decorators_allow_and_deny():
    app = make_app(FakeGuard(True))
    client = app.test_client()
    assert client.get("/open").status_code == 200
    assert client.get("/guarded").status_code == 200
    assert client.get("/guard-deco").status_code == 200

    app2 = make_app(FakeGuard(False, "nope"))
    c2 = app2.test_client()
    assert c2.get("/open").status_code == 200
    assert c2.get("/guarded").status_code == 403
    assert c2.get("/guard-deco").status_code == 403

