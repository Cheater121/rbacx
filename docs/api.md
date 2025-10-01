
# API Reference

::: rbacx.core.engine
___
::: rbacx.core.model
___
::: rbacx.core.policy
___
::: rbacx.core.policyset
___
::: rbacx.core.ports
___
::: rbacx.logging.decision_logger
___
::: rbacx.core.obligations
___
::: rbacx.core.cache
___
::: rbacx.core.roles
___
::: rbacx.store
___
::: rbacx.policy
___
::: rbacx.store.file_store
___
::: rbacx.store.s3_store
___
::: rbacx.store.http_store
___
::: rbacx.adapters.asgi
___
::: rbacx.adapters.asgi_logging
___
::: rbacx.adapters.flask
___
::: rbacx.adapters.django.middleware
___
::: rbacx.adapters.django.trace
___
::: rbacx.adapters.litestar
___

## Decision object

Fields returned by `Guard.evaluate*`:

- `allowed: bool`
- `effect: "permit" | "deny"`
- `obligations: List[Dict[str, Any]]`
- `challenge: Optional[str]`
- `rule_id: Optional[str]`
- `policy_id: Optional[str]`
- `reason: Optional[str]`
___

### YAML policies

All built-in policy sources accept JSON and, with the optional `rbacx[yaml]` extra, YAML.

- File: detected by extension `.yaml` / `.yml`.
- HTTP: detected by `Content-Type` (e.g., `application/yaml`, `application/x-yaml`, `text/yaml`) or URL suffix.
- S3: detected by key suffix `.yaml` / `.yml`.

> Internally YAML is parsed and validated against the same JSON Schema as JSON.
