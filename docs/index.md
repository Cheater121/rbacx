# RBACX

**RBAC + ABAC + ReBAC authorization for Python** with a clean architecture, declarative JSON policies, framework adapters, and optional hot reloading.

---

## Inspiration & Philosophy

RBACX is inspired by:
- **OWASP-aligned practices** like *deny by default* and *least privilege*.
- The recurring **pain for Python developers** switching between projects with inconsistent authorization stacks.
- The **XACML** model (policies, rules, effects, combining algorithms, obligations), **simplified** and made friendlier for web developers using JSON and a Python-first API.

> Our philosophy: **security should be understandable and ergonomic for developers** so that correct authorization becomes the *path of least resistance*.

---

## What you get

- **RBAC + ABAC + ReBAC** in a single engine (role checks, attribute conditions, and relationship checks).
- **Declarative policies** (JSON/YAML or Python dict) with compact operators, including time operators and `rel` condition for relationship checks.
- **Secure defaults**: `deny-overrides` by default; also `permit-overrides`, `first-applicable`.
- **Role hierarchy** via resolvers (`StaticRoleResolver` and custom implementations).
- **Explainable decisions** (`allowed`, `effect`, `reason`, `rule_id`) and **obligations** (e.g., require MFA).
- **ReBAC providers**: optional integrations for **OpenFGA** and **SpiceDB/Authzed**.
- **Hot reload** from file/HTTP/S3 using ETag checks.
- **Adapters** for FastAPI/Starlette, Flask, Django/DRF, Litestar.
- **Observability**: logging hooks and metrics sinks (Prometheus/OpenTelemetry).
- **Optional decision caching**: pluggable cache (`AbstractCache`) per `Guard`, with in-memory LRU+TTL default. Enable via `cache` / `cache_ttl`; clear with `guard.clear_cache()`.
- **CLI & linting**: `rbacx validate` to schema‑check, `rbacx lint` to lint, `rbacx check` to validate then lint.
- **Test coverage** around **100%** across core decision paths.

---

## Quick start

### 1) Install
```bash
pip install rbacx
```

### 2) Define a minimal policy (JSON)
```json
{
  "algorithm": "deny-overrides",
  "rules": [
    {
      "id": "allow_read_public",
      "effect": "permit",
      "actions": ["read"],
      "resource": { "type": "doc" },
      "condition": { "==": [ { "attr": "resource.visibility" }, "public" ] },
      "obligations": [ { "type": "require_mfa", "on": "permit" } ]
    }
  ]
}
```

### 3) Evaluate in Python
```python
from rbacx import Guard

policy = {...}  # load JSON as a dict
g = Guard(policy)

decision = g.evaluate_sync(
    subject={"id": "u1", "roles": ["reader"]},
    action="read",
    resource={"type": "document", "visibility": "public"},
    context={"mfa": True},
)

assert decision.allowed is True
print(decision.effect, decision.reason, decision.rule_id, decision.obligations)
```

### 4) (Optional) Use a web adapter

**FastAPI**
```python
from fastapi import FastAPI, Request
from rbacx import Action, Context, Guard, Resource, Subject
from rbacx.adapters.fastapi import require_access

app = FastAPI()

policy = {...}  # reuse the policy from above or define one here
guard = Guard(policy)

def build_env(request: Request):
    user = request.headers.get("x-user", "anonymous")
    return Subject(id=user, roles=["user"]), Action("read"), Resource(type="doc"), Context()


@app.get("/docs")
@require_access(guard, build_env)
def docs():
    return {"ok": True}
```

---

## Documentation map

**Start here**
- [Quickstart](quickstart.md)
- [Why choose RBACX](why_choose.md)
- [Highlights](highlights.md)
- [Strategies](strategies.md)

**Core concepts**
- [Architecture](architecture.md)
- [Security model](security.md)
- [Explainability (reasons & obligations)](reasons.md)
- [Role hierarchy](roles.md)
- [Audit mode](audit_mode.md)
- [Obligations](obligations.md)
- [Decision caching](caching.md)
- [Types](types.md)

**Policy**
- [Policy authoring](policy_authoring.md)
- [Policy catalog](policy_catalog.md)
- [Time operators](time_operators.md)
- [Policy loading (hot reload)](policy_loading.md)
- [Policy stores](policy_stores.md)
- [Custom Policy Source](custom_policy_source.md)
- [HTTP mapping](http_mapping.md)

**Integration**
- [Web adapters](web_adapters.md)
- [Custom adapters](adapters.md)
- [Try examples](try_examples.md)

**Observability**
- [Metrics](metrics.md)
- [OpenTelemetry](otel_metrics.md)
- [Prometheus](prometheus.md)
- [Logging](logging.md)
- [Policy diagnostics](diagnostics.md)
- [Observability stack](observability_stack.md)

**Performance & operations**
- [Performance guide](performance.md)
- [Benchmarks](benchmarks.md)
- [CI](ci.md)
- [Migration (RBAC→ABAC)](migration_rbac_to_abac.md)

**Reference**
- [Public API](api.md)
