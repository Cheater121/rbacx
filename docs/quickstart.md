# Quickstart

This page shows how to install RBACX and its optional extras.

RBACX keeps the **core lightweight** and avoids pulling heavy dependencies by default.
This helps keep it framework‑agnostic and reduces conflicts in real projects.
If you need integrations or helpers, install **extras** selectively.

## Install

Minimal install:

```bash
pip install rbacx
```

## Optional features (extras)

| Extra              | Enables                                         | Install command                            |
|--------------------|--------------------------------------------------|--------------------------------------------|
| `adapters-fastapi` | FastAPI / Starlette adapters                     | `pip install rbacx[adapters-fastapi]`      |
| `adapters-flask`   | Flask adapters                                   | `pip install rbacx[adapters-flask]`        |
| `adapters-drf`     | Django + DRF adapters                            | `pip install rbacx[adapters-drf]`          |
| `adapters-litestar`| Litestar adapters                                | `pip install rbacx[adapters-litestar]`     |
| `metrics`          | Prometheus client metrics                        | `pip install rbacx[metrics]`               |
| `otel`             | OpenTelemetry API/SDK helpers                    | `pip install rbacx[otel]`                  |
| `http`             | HTTP policy source (requests)                    | `pip install rbacx[http]`                  |
| `s3`               | S3 policy source (boto3)                         | `pip install rbacx[s3]`                    |
| `dates`            | Time operators support (python‑dateutil)         | `pip install rbacx[dates]`                 |
| `yaml`             | YAML policies support                            | `pip install rbacx[yaml]`                  |


You can combine extras:

```bash
pip install 'rbacx[adapters-fastapi,metrics,otel]'
```

> **Why a separate YAML extra?**
> YAML is optional. If you want to author policies in YAML, install `rbacx[yaml]`.
> YAML’s official media type is `application/yaml` (see RFC 9512). For security, we parse YAML with `yaml.safe_load`.

## Define a policy (JSON or YAML)

Both JSON and YAML are supported. They’re parsed into a `dict` and validated against the same JSON Schema.

**JSON:**

```json
{
  "algorithm": "permit-overrides",
  "rules": [
    {"id": "p1", "effect": "permit", "actions": ["read"], "resource": {"type": "doc"}},
    {"id": "d1", "effect": "deny",   "actions": ["delete"], "resource": {"type": "doc"}}
  ]
}
```

**YAML:**

```yaml
algorithm: permit-overrides
rules:
  - id: p1
    effect: permit
    actions: [read]
    resource: { type: doc }
  - id: d1
    effect: deny
    actions: [delete]
    resource: { type: doc }
```

## Load a policy

You can load policies from **files**, **HTTP**, or **S3** or create your policy source.

```python
from rbacx import Guard
from rbacx.store.file_store import FilePolicySource
from rbacx.store.http_store import HTTPPolicySource
from rbacx.store.s3_store import S3PolicySource

guard = Guard(policy=FilePolicySource("examples/policies/ok_policy.json").load())
# guard = Guard(policy=FilePolicySource("examples/policies/ok_policy.yaml").load())  # requires rbacx[yaml]

# HTTP: YAML detected by Content-Type (application/yaml) or URL suffix .yaml/.yml
# guard = Guard(policy=HTTPPolicySource("https://example.com/policy.yaml").load())

# S3: YAML detected by key suffix .yaml/.yml
# guard = Guard(policy=S3PolicySource("s3://my-bucket/policy.yaml").load())
```

## CLI

Lint a policy file (JSON or YAML):

```bash
rbacx lint --policy examples/policies/ok_policy.json
rbacx lint --policy examples/policies/ok_policy.yaml
rbacx lint --policy examples/policies/bad_policy.json
rbacx lint --policy examples/policies/bad_policy.yaml
```

The CLI prints JSON diagnostics. A non-empty list means warnings/errors were found.

---
Need more? See the full docs site for adapters, middleware, metrics, and advanced configuration.


### ReBAC (local) in 60 seconds

```python
from rbacx.core.engine import Guard
from rbacx.rebac.local import LocalRelationshipChecker, InMemoryRelationshipStore, This

# 1) Build a tiny graph in memory
store = InMemoryRelationshipStore()
store.add("document:doc1", "owner", "user:alice")
# define inheritance / computed usersets in the checker
checker = LocalRelationshipChecker(
    store,
    rules={
        "document": {"viewer": [This(),], "owner": [This()]}
    },
)

# 2) Policy uses the 'rel' condition
policy = {
    "id": "rebac-local-demo",
    "alg": "deny-overrides",
    "rules": [
        {"id": "can-read", "when": {"rel": "viewer"}, "effect": "permit",
         "actions": ["document.read"], "resources": [{"type": "document"}]}
    ],
}

guard = Guard(policy, relationship_checker=checker)
```
