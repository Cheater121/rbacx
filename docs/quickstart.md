# Quickstart

This guide gets you productive with **RBACX** quickly.

## Install

Minimal install:

```bash
pip install rbacx
```

### Extras

RBACX ships optional extras so you can install only what you need:

```bash
# Framework adapters
pip install "rbacx[adapters-fastapi]"
pip install "rbacx[adapters-flask]"
pip install "rbacx[adapters-django]"
pip install "rbacx[adapters-litestar]"
pip install "rbacx[adapters-drf]"

# HTTP/S3 policy sources
pip install "rbacx[http]"
pip install "rbacx[s3]"

# YAML policy support
pip install "rbacx[yaml]"
```

> **Why a separate YAML extra?**
> YAML is optional. If you want to author policies in YAML, install `rbacx[yaml]`.
> YAML’s official media type is `application/yaml` (see RFC 9512). For security, we parse YAML with `yaml.safe_load`. citeturn0search16turn0search5turn0search21

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

You can load policies from **files**, **HTTP**, or **S3**.

```python
from rbacx import Guard
from rbacx.store.file_store import FilePolicySource
from rbacx.store.http_store import HTTPPolicySource
from rbacx.store.s3_store import S3PolicySource

guard = Guard(policy=FilePolicySource("examples/policies/ok_policy.json"))
# guard = Guard(policy=FilePolicySource("examples/policies/ok_policy.yaml"))  # requires rbacx[yaml]

# HTTP: YAML detected by Content-Type (application/yaml) or URL suffix .yaml/.yml
# guard = Guard(policy=HTTPPolicySource("https://example.com/policy.yaml"))

# S3: YAML detected by key suffix .yaml/.yml
# guard = Guard(policy=S3PolicySource("s3://my-bucket/policy.yaml"))
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
