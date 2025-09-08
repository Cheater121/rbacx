
# Web framework adapters

RBACX ships simple adapters for popular frameworks.

## FastAPI (dependency)
```python
from fastapi import FastAPI, Depends, Request
from rbacx.adapters.fastapi import require_access
from rbacx.core.engine import Guard

guard = Guard(policy)

def build_env(request: Request):
    user_id = request.headers.get("x-user", "anonymous")
    from rbacx.core.model import Subject, Resource, Action, Context
    return Subject(id=user_id), Action("read"), Resource(type="doc"), Context()

app = FastAPI()

@app.get("/docs", dependencies=[Depends(require_access(guard, build_env, add_headers=True))])
async def docs(): return {"ok": True}
```

## Starlette middleware (works with FastAPI)
```python
from rbacx.adapters.starlette import RBACXMiddleware
app.add_middleware(RBACXMiddleware, guard=guard, build_env=build_env, add_headers=True)
```

## Flask decorator
```python
from flask import Flask, request
from rbacx.adapters.flask import require_access

app = Flask(__name__)
@app.route('/docs')
@require_access(guard, lambda _req: build_env(request), add_headers=True)
def docs(): return {"ok": True}
```

## Django REST Framework
```python
from rbacx.adapters.drf import make_permission
RBACXPermission = make_permission(guard, build_env)

class MyView(APIView):
    permission_classes = [RBACXPermission]
```
