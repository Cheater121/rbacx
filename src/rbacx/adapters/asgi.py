from __future__ import annotations

import json
import logging
from typing import Any, Iterable, Optional, Tuple

from ..core.engine import Guard
from ._common import EnvBuilder

logger = logging.getLogger("rbacx.adapters.asgi")


class RbacxMiddleware:
    """Framework-agnostic ASGI middleware.

    Modes:
      - "inject": only injects guard into scope.
      - "enforce": evaluates access for HTTP requests when build_env is provided.

    Security:
      - Does not leak denial reasons in the response body.
      - If `add_headers=True`, attaches `X-RBACX-*` headers on deny.
    """

    def __init__(
        self,
        app: Any,
        *,
        guard: Guard,
        mode: str = "enforce",
        build_env: EnvBuilder | None = None,
        add_headers: bool = False,
    ) -> None:
        self.app = app
        self.guard = guard
        self.mode = mode
        self.build_env = build_env
        self.add_headers = add_headers

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        # Always inject the guard for downstream usage
        scope["rbacx_guard"] = self.guard

        # Enforce only for HTTP, only when env builder is provided
        if scope.get("type") == "http" and self.mode == "enforce" and self.build_env is not None:
            subject, action, resource, context = self.build_env(scope)
            decision = await self.guard.evaluate_async(subject, action, resource, context)
            if not decision.allowed:
                headers: list[Tuple[bytes, bytes]] = []
                if self.add_headers:
                    if decision.reason:
                        headers.append((b"x-rbacx-reason", str(decision.reason).encode("utf-8")))
                    rule_id = getattr(decision, "rule_id", None)
                    if rule_id:
                        headers.append((b"x-rbacx-rule", str(rule_id).encode("utf-8")))
                    policy_id = getattr(decision, "policy_id", None)
                    if policy_id:
                        headers.append((b"x-rbacx-policy", str(policy_id).encode("utf-8")))
                await self._send_json(send, 403, {"detail": "Forbidden"}, extra_headers=headers)
                return

        await self.app(scope, receive, send)

    async def _send_json(
        self,
        send: Any,
        status: int,
        payload: dict,
        *,
        extra_headers: Optional[Iterable[Tuple[bytes, bytes]]] = None,
    ) -> None:
        """Send a minimal JSON response via raw ASGI messages."""
        body = json.dumps(payload).encode("utf-8")
        headers: list[Tuple[bytes, bytes]] = [
            (b"content-type", b"application/json; charset=utf-8"),
            (b"content-length", str(len(body)).encode("ascii")),
        ]
        if extra_headers:
            headers.extend(extra_headers)
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": body})
