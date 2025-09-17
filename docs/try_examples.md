# Running the examples (Django, DRF, FastAPI, Flask, Litestar)

This guide shows how to run **all** demo apps under `examples/`, exactly as implemented in the sources.

- `examples/django_demo` — plain Django
- `examples/drf_demo` — Django REST Framework
- `examples/fastapi_demo` — FastAPI
- `examples/flask_demo` — Flask
- `examples/litestar_demo` — Litestar

## Install from PyPI (extras)

Install only what you need via extras from PyPI (no editable install):

```bash
# choose one or more:
pip install rbacx[adapters-drf]
pip install rbacx[adapters-fastapi]
pip install rbacx[adapters-flask]
pip install rbacx[adapters-litestar]
# or everything used by the examples:
pip install rbacx[examples]
```

> Depending on your shell you may need quotes: `pip install "rbacx[adapters-drf]"`.

---

## Django (`examples/django_demo`)

```bash
python examples/django_demo/manage.py migrate
python examples/django_demo/manage.py runserver 127.0.0.1:8000
# Test:
curl -i http://127.0.0.1:8000/health
curl -i http://127.0.0.1:8000/doc
```

**Endpoints**
- `GET /health` → `{"ok": true}`
- `GET /doc` → JSON decision result:
  - Allowed: `{ "allowed": true, "docs": ["doc-1", "doc-2"] }`
  - Denied: `{ "allowed": false, "reason": "..." }` (HTTP 403)

The demo uses a tiny in-repo guard (see `rbacx_demo/rbacx_factory.py`). The `docs` view normalizes a decision-like object and returns JSON accordingly.

---

## Django REST Framework (`examples/drf_demo`)

```bash
python examples/drf_demo/manage.py migrate
python examples/drf_demo/manage.py runserver 127.0.0.1:8001
# Test:
curl -i http://127.0.0.1:8001/docs
```

**Endpoint**
- `GET /docs` → `{ "ok": true }` on success

Access control is enforced with `rbacx.adapters.drf.make_permission(guard, build_env)`, see `docsapp/views.py`. The example policy in `docsapp/policy.json` permits `read` on resources of type `"doc"`.

---

## FastAPI (`examples/fastapi_demo`)

```bash
uvicorn examples.fastapi_demo.app:app --reload --port 8002
# Test:
curl -i http://127.0.0.1:8002/ping
curl -i http://127.0.0.1:8002/doc
```

**Endpoints**
- `GET /ping` → `{"pong": true}`
- `GET /doc`  → `{"ok": true}` on success

The dependency `require_access(guard, build_env, add_headers=True)` checks access before the handler. `build_env` reads `X-User` (optional) and constructs: `Subject(id, roles=["user"])`, `Action("read")`, `Resource(type="doc")`, `Context()`.

---

## Flask (`examples/flask_demo`)

```bash
flask --app examples/flask_demo/app.py run --port 8003
# Test:
curl -i http://127.0.0.1:8003/ping
curl -i http://127.0.0.1:8003/doc
```

**Endpoints**
- `GET /ping` → `{"pong": true}`
- `GET /doc` → protected by `@require_access(...)`

`build_env` also reads the optional `X-User` header and sets roles to `["user"]`.

---

## Litestar (`examples/litestar_demo`)

```bash
uvicorn examples.litestar_demo.app:app --reload --port 8004
# (optional structured logs)
# uvicorn app:app --reload --port 8004 --log-config ../logging/uvicorn_logging_json.yml

# Test:
curl -i http://127.0.0.1:8004/health
curl -i http://127.0.0.1:8004/docs/1
```

**Endpoints**
- `GET /health` → `{"ok": true}`
- `GET /docs/{doc_id}` → returns a JSON object with `{"allowed": <bool>}` computed by the guard, see `get_doc` handler. The resource type is `"doc"`.

---

## Notes

- Authorization failures generally return **403** with a short JSON body. If your decision includes an **authentication challenge** (e.g., MFA required), returning **401** with an appropriate `WWW-Authenticate` or custom challenge header may be more appropriate. See **Mapping Decision reasons to HTTP responses**.
- Only the FastAPI and Flask demos read `X-User`; DRF uses `request.user`; Django demo uses a hard-coded demo subject with the `demo_user` role.
