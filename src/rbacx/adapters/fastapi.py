from collections.abc import Awaitable, Callable

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
