# Quickstart

This page shows how to install RBACX and its optional extras.

RBACX keeps the **core lightweight** and avoids pulling heavy dependencies by default.
This helps keep it framework‑agnostic and reduces conflicts in real projects.
If you need integrations or helpers, install **extras** selectively.

## Install

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

You can combine extras:

```bash
pip install 'rbacx[adapters-fastapi,metrics,otel]'
```

## CLI

RBACX ships a simple linter for policies.

```bash
pip install rbacx
rbacx lint --policy examples/policies/ok_policy.json
rbacx lint --policy examples/policies/bad_policy.json
```

See the repository **README** for a minimal policy example and a short Hot‑Reload snippet.
