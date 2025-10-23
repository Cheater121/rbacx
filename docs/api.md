# API Reference

::: rbacx.core.engine

---

::: rbacx.core.model

---

::: rbacx.core.policy

---

::: rbacx.core.policyset

---

::: rbacx.core.ports

---

::: rbacx.core.relctx

---

::: rbacx.logging.decision_logger

---

::: rbacx.logging.context

---

::: rbacx.core.obligations

---

::: rbacx.core.cache

---

::: rbacx.core.roles

---

::: rbacx.policy

---

::: rbacx.rebac

---

::: rbacx.store.file_store

---

::: rbacx.store.s3_store

---

::: rbacx.store.http_store

---

::: rbacx.adapters.asgi

---

::: rbacx.adapters.asgi_logging

---

::: rbacx.adapters.asgi_accesslog

---

::: rbacx.adapters.flask

---

::: rbacx.adapters.django.middleware

---

::: rbacx.adapters.django.trace

---

::: rbacx.adapters.litestar

---

## Decision object

Fields returned by `Guard.evaluate*`:

* `allowed: bool`
* `effect: "permit" | "deny"`
* `obligations: List[Dict[str, Any]]`
* `challenge: Optional[str]`
* `rule_id: Optional[str]`
* `policy_id: Optional[str]`
* `reason: Optional[str]`

---

### YAML policies

All built-in policy sources accept JSON and, with the optional `rbacx[yaml]` extra, YAML.

* File: detected by extension `.yaml` / `.yml`.
* HTTP: detected by `Content-Type` (e.g., `application/yaml`, `application/x-yaml`, `text/yaml`) or URL suffix.
* S3: detected by key suffix `.yaml` / `.yml`.

> Internally YAML is parsed and validated against the same JSON Schema as JSON.
