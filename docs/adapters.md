
# Adapters

FastAPI / Flask / Litestar / Django examples are under `examples/`.


## Enforcement helpers

### FastAPI
```python
from fastapi import FastAPI, Depends, Request
from rbacx.adapters.fastapi import require_access
from rbacx import Guard
from rbacx.core.model import Subject, Resource, Action, Context

# Demo policy (permit-all for brevity)
policy = {"rules": [{"effect": "permit"}]}
guard = Guard(policy)

def build_env(request: Request):
    user = request.headers.get("x-user", "anonymous")
    return Subject(id=user), Action("read"), Resource(type="doc"), Context()

app = FastAPI()

@app.get("/secure", dependencies=[Depends(require_access(guard, build_env, add_headers=True))])
def secure():
    return {"ok": True}
```

### Flask
```python
from flask import Flask, request
from rbacx.adapters.flask import require_access
from rbacx import Guard
from rbacx.core.model import Subject, Resource, Action, Context

# Demo policy (permit-all for brevity)
policy = {"rules": [{"effect": "permit"}]}
guard = Guard(policy)

def build_env(req=None):
    req = req or request
    user = req.headers.get("x-user", "anonymous")
    return Subject(id=user), Action("read"), Resource(type="doc"), Context()

app = Flask(__name__)

@app.get("/secure")
@require_access(guard, build_env, add_headers=True)
def secure():
    return {"ok": True}
```

### Django
```python
from rbacx.adapters.django.decorators import require

@require("read", "doc")
def my_view(request):
    # Tip: provide request.rbacx_guard via RbacxDjangoMiddleware
    ...
```

### Litestar
```python
from litestar import Litestar, get
from litestar.di import Provide
from rbacx.adapters.litestar_guard import require
from rbacx import Guard

# Demo policy (permit-all for brevity)
policy = {"rules": [{"effect": "permit"}]}
guard = Guard(policy)

@get(
    "/secure",
    dependencies={
        "check": Provide(require("read", "doc")),   # performs the access check
        "guard": Provide(lambda: guard),            # injected into the checker
    },
)
def secure() -> dict:
    return {"ok": True}

app = Litestar(route_handlers=[secure])
```

## S3 policy source
```python
from rbacx import Guard
from rbacx import HotReloader
from rbacx.store import S3PolicySource

# Demo guard
guard = Guard({"rules": [{"effect": "permit"}]})

# Configure S3 policy source (bucket/key form)
source = S3PolicySource("s3://policies/rbac.json")

# Hot reloader (background polling)
reloader = HotReloader(guard, source, poll_interval=1.0)
reloader.start()
```
