
# Adapters

FastAPI / Flask / Litestar / Django examples are under `examples/`.


## Enforcement helpers

### FastAPI
```python
from fastapi import FastAPI, Depends
from rbacx.adapters.fastapi_guard import make_guard_dependency

app = FastAPI()

dep = make_guard_dependency(guard)

@app.get("/secure", dependencies=[Depends(dep)])
def secure():
    return {"ok": True}
```

### Flask
```python
from rbacx.adapters.flask_guard import require

@app.get("/secure")
@require("read", "doc")
def secure():
    return {"ok": True}
```

### Django
```python
from rbacx.adapters.django.decorators import require

@require("read", "doc")
def my_view(request):
    ...
```

### Litestar
```python
from litestar import Litestar, get
from litestar.di import Provide
from rbacx.adapters.litestar_guard import require
from rbacx.adapters.litestar import provide_guard

@get("/secure", dependencies={"check": Provide(require("read","doc")), "rbacx_guard": Provide(provide_guard(guard))})
def secure() -> dict: return {"ok": True}
```

## S3 policy source
```python
from rbacx.storage.s3 import S3PolicySource
source = S3PolicySource(bucket="policies", key="rbac.json")
reloader = HotReloader(guard, source, poll_interval=1.0)
```
