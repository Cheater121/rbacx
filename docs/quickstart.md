See README for quickstart; includes policy example and HotReloader.

## Optional features (extras)/Installation

RBACX keeps the **core lightweight** and avoids pulling heavy dependencies by default — to stay framework-agnostic and minimize conflicts in real projects.  
If you need integrations or helpers, install **extras** selectively.

### Common extras

| Extra | What it enables | Install |
|---|---|---|
| `adapters-fastapi` | FastAPI / Starlette adapter | `pip install rbacx[adapters-fastapi]` |
| `adapters-flask` | Flask adapter | `pip install rbacx[adapters-flask]` |
| `adapters-drf` | Django + DRF adapter | `pip install rbacx[adapters-drf]` |
| `adapters-litestar` | Litestar adapter | `pip install rbacx[adapters-litestar]` |
| `metrics` | Prometheus client metrics | `pip install rbacx[metrics]` |
| `otel` | OpenTelemetry (API/SDK) | `pip install rbacx[otel]` |
| `dates` | Date/time helpers for time operators | `pip install rbacx[dates]` |
| `http` | HTTP policy source (`requests`) | `pip install rbacx[http]` |
| `s3` | S3 policy source (`boto3`) | `pip install rbacx[s3]` |
| `validate` | Policy validation (`jsonschema`) | `pip install rbacx[validate]` |
| `docs` | Build docs (MkDocs toolchain) | `pip install rbacx[docs]` |
| `tests` | Test tooling (pytest/coverage) | `pip install rbacx[tests]` |

You can combine extras, e.g.:

```bash
pip install 'rbacx[adapters-fastapi,metrics,otel]'
```


## CLI
```bash
pip install rbacx
rbacx validate --policy examples/fastapi_demo/policy.JSON  # required `validate` dependencies
rbacx eval --policy examples/fastapi_demo/policy.json --subject u1 --action read --resource-type article --context '{"mfa": true}'
```
