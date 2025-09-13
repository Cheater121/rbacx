
# API Reference

::: rbacx.core.engine
::: rbacx.core.model
::: rbacx.core.policy
::: rbacx.core.policyset
::: rbacx.core.ports
::: rbacx.core.obligations
::: rbacx.store
::: rbacx.policy.loader
::: rbacx.store.file_store
::: rbacx.store.s3_store
::: rbacx.store.http_store
::: rbacx.adapters.asgi
::: rbacx.adapters.asgi_logging
::: rbacx.adapters.flask
::: rbacx.adapters.django.middleware
::: rbacx.adapters.django.trace
::: rbacx.adapters.litestar
::: rbacx.telemetry.decision_log


## Decision object

Fields returned by `Guard.evaluate*`:

- `allowed: bool`
- `effect: "permit" | "deny"`
- `obligations: List[Dict[str, Any]]`
- `challenge: Optional[str]`
- `rule_id: Optional[str]`
- `policy_id: Optional[str]`
- `reason: Optional[str]`
