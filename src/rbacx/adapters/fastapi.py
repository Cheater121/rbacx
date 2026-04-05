from collections.abc import Awaitable, Callable, Sequence

try:  # Optional dependency boundary
    from fastapi import HTTPException, Request  # type: ignore[import-not-found]
except Exception:  # pragma: no cover
    HTTPException = None  # type: ignore
    Request = None  # type: ignore

from ..core.engine import Guard
from ._common import EnvBuilder


def require_access(
    guard: Guard,
    build_env: EnvBuilder,
    *,
    add_headers: bool = False,
) -> Callable[[Request], Awaitable[None]]:
    """Return a FastAPI dependency that enforces access with optional deny headers."""

    async def dependency(request: Request) -> None:
        """Async-only dependency for FastAPI: always uses Guard.evaluate_async."""
        if HTTPException is None:  # pragma: no cover
            raise RuntimeError("fastapi is required for adapters.fastapi")

        sub, act, res, ctx = build_env(request)

        decision = await guard.evaluate_async(sub, act, res, ctx)
        if decision.allowed:
            return

        # By default do not leak reasons. If explicitly enabled, surface via headers only.
        headers: dict[str, str] = {}
        if add_headers:
            if decision.reason is not None:
                headers["X-RBACX-Reason"] = str(decision.reason)
            rule_id = getattr(decision, "rule_id", None)
            if rule_id is not None:
                headers["X-RBACX-Rule"] = str(rule_id)
            policy_id = getattr(decision, "policy_id", None)
            if policy_id is not None:
                headers["X-RBACX-Policy"] = str(policy_id)

        # Keep body generic to avoid information disclosure.
        # HTTPException accepts headers: Optional[Dict[str, Any]]
        raise HTTPException(status_code=403, detail="Forbidden", headers=headers)

    return dependency


def require_batch_access(
    guard: Guard,
    actions_resources: Sequence[tuple[str, str]],
    build_subject: Callable,
    *,
    timeout: float | None = None,
) -> Callable:
    """Return a FastAPI dependency that evaluates multiple access checks in one batch.

    Designed for UI endpoints that need to know which actions are permitted for
    a given user at once (e.g. to show/hide buttons) — avoids N sequential
    ``evaluate_async`` calls.

    Args:
        guard: the :class:`~rbacx.core.engine.Guard` instance.
        actions_resources: sequence of ``(action, resource_type)`` string pairs
            that define the checks to perform.  Each pair maps to one
            :class:`~rbacx.core.model.Decision` in the returned list.
        build_subject: callable ``(request) -> Subject`` that extracts the
            subject from the FastAPI request.  Only the subject varies per
            request; action and resource are taken from *actions_resources*.
        timeout: optional wall-clock deadline in seconds for the entire batch.
            ``None`` means no deadline.  When exceeded
            :class:`asyncio.TimeoutError` propagates as a 500 error.

    Returns:
        A FastAPI dependency that, when injected, resolves to a
        ``list[Decision]`` — one entry per ``(action, resource_type)`` pair,
        in the same order.

    Example::

        from rbacx.adapters.fastapi import require_batch_access
        from rbacx import Subject, Action, Resource, Context

        def build_subject(request: Request) -> Subject:
            role = request.headers.get("X-Role", "viewer")
            return Subject(id="user", roles=[role])

        @app.get("/ui-state")
        async def ui_state(
            decisions=Depends(
                require_batch_access(
                    guard,
                    [("read", "document"), ("write", "document"), ("delete", "document")],
                    build_subject,
                )
            )
        ):
            return {
                "can_read":   decisions[0].allowed,
                "can_write":  decisions[1].allowed,
                "can_delete": decisions[2].allowed,
            }
    """
    from ..core.model import Action, Context, Resource  # noqa: PLC0415

    async def dependency(request: Request) -> list:
        if Request is None:  # pragma: no cover
            raise RuntimeError("fastapi is required for adapters.fastapi")

        subject = build_subject(request)
        requests = [
            (subject, Action(action), Resource(type=rtype), Context())
            for action, rtype in actions_resources
        ]
        return await guard.evaluate_batch_async(requests, timeout=timeout)

    return dependency
