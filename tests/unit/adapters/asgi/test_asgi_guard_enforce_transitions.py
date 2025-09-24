import inspect
import json

import pytest


def _find_guard_middleware(mod):
    """
    Heuristically find the guard middleware class in rbacx.adapters.asgi by
    trying to instantiate candidates with the expected signature. Returns the class.
    """

    def try_build(cls):
        try:
            cls(
                lambda *_: None,
                guard=object(),
                build_env=lambda s: ("s", "a", "r", {"ctx": True}),
                mode="enforce",
                add_headers=True,
            )
            return True
        except Exception:
            return False

    for _, obj in inspect.getmembers(mod, inspect.isclass):
        if obj.__module__ != mod.__name__:
            continue
        if callable(obj) and try_build(obj):
            return obj
    pytest.skip("No guard middleware class found in rbacx.adapters.asgi")


class Decision:
    def __init__(self, allowed, reason=None, rule_id=None, policy_id=None):
        self.allowed = allowed
        self.reason = reason
        self.rule_id = rule_id
        self.policy_id = policy_id


def _http_scope():
    return {
        "type": "http",
        "http_version": "1.1",
        "method": "GET",
        "path": "/deny",
        "raw_path": b"/deny",
        "headers": [(b"host", b"test")],
        "query_string": b"",
        "scheme": "http",
        "client": ("127.0.0.1", 12345),
        "server": ("testserver", 80),
    }


def _build_env(scope):
    return ("sub", "act", "res", {"path": scope.get("path")})


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "reason, rule_id, policy_id, expected_keys",
    [
        # only reason -> covers True branch for reason, False for rule/policy
        ("not-allowed", None, None, {b"x-rbacx-reason"}),
        # only rule -> covers True for rule, False for reason/policy
        (None, "rule-42", None, {b"x-rbacx-rule"}),
        # only policy -> True for policy, False для reason/rule
        (None, None, "policy-main", {b"x-rbacx-policy"}),
        # none -> все внутренние if дадут False (headers=[], но add_headers=True)
        (None, None, None, set()),
    ],
)
async def test_enforce_deny_header_transitions(reason, rule_id, policy_id, expected_keys):
    """
    Covers transitions:
      - 48->62 (общее ветвление add_headers-блока с различными наборами полей),
      - 51->53 (reason True/False),
      - 54->56 (rule_id True/False),
      - 57->59 (policy_id True/False).
    """
    from rbacx.adapters import asgi as mod

    MW = _find_guard_middleware(mod)

    class Guard:
        async def evaluate_async(self, *_a, **_k):
            return Decision(allowed=False, reason=reason, rule_id=rule_id, policy_id=policy_id)

    inner_called = {"flag": False}

    async def inner_app(scope, receive, send):
        inner_called["flag"] = True
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    app = MW(
        inner_app,
        guard=Guard(),
        build_env=_build_env,
        mode="enforce",
        add_headers=True,  # важно: входим в блок добавления заголовков
    )

    sent = []

    async def _receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def _send(message):
        sent.append(message)

    await app(_http_scope(), _receive, _send)

    # Должен сработать deny: inner_app не вызывается
    assert inner_called["flag"] is False

    # Проверяем старт ответа
    starts = [m for m in sent if m.get("type") == "http.response.start"]
    assert starts, "no http.response.start"
    start = starts[0]
    assert start["status"] == 403

    hdrs = dict(start["headers"])
    # Базовые JSON-заголовки из _send_json
    assert hdrs[b"content-type"] == b"application/json; charset=utf-8"

    # Диагностические заголовки: сравним ключи
    diag_keys = {k for k in hdrs.keys() if k.startswith(b"x-rbacx-")}
    assert diag_keys == expected_keys

    # Проверим тело и content-length
    bodies = [m for m in sent if m.get("type") == "http.response.body"]
    assert bodies, "no http.response.body"
    body = bodies[0]["body"]
    assert json.loads(body.decode("utf-8")) == {"detail": "Forbidden"}
    assert hdrs[b"content-length"] == str(len(body)).encode("ascii")
