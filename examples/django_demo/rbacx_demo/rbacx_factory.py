# Minimal demo guard factory for Django demo without importing internal Policy/Rule
# The middleware will call build_guard() and attach the returned object to request as `rbacx_guard`.
# The guard implements a tiny `evaluate_sync` compatible surface for the demo.
from typing import Any, Dict, Iterable


class DemoGuard:
    def __init__(self, required_role: str = "demo_user"):
        self.required_role = required_role

    def evaluate_sync(
        self, subject: Any, action: str, resource: str, context: Dict[str, Any] | None = None
    ):
        roles: Iterable[str] = getattr(subject, "roles", []) or []
        allowed = self.required_role in roles
        # Return a dict to stay flexible regardless of the engine's Decision type
        return {"allowed": bool(allowed), "reason": f"requires role '{self.required_role}'"}


def build_guard() -> DemoGuard:
    # In a real app you might load configuration or policies here.
    return DemoGuard(required_role="demo_user")
