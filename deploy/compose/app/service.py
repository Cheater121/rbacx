from fastapi import Depends, FastAPI, Request, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from rbacx import Action, Context, Guard, Resource, Subject
from rbacx.adapters.fastapi import require_access
from rbacx.metrics.prometheus import PrometheusMetrics

policy = {
    "rules": [
        {"id": "doc_read", "effect": "permit", "actions": ["read"], "resource": {"type": "doc"}}
    ]
}
metrics = PrometheusMetrics()
guard = Guard(policy, metrics=metrics)


def build_env(request: Request):
    user = request.headers.get("x-user", "anonymous")
    return Subject(id=user, roles=["user"]), Action("read"), Resource(type="doc"), Context()


app = FastAPI()


@app.get("/ping")
def ping():
    return {"pong": True}


@app.get("/doc", dependencies=[Depends(require_access(guard, build_env, add_headers=True))])
async def doc():
    return {"ok": True}


@app.get("/metrics")
def metrics_endpoint():
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)
