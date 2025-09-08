
from fastapi import FastAPI, Depends, Request, Response
from rbacx.adapters.fastapi import require_access
from rbacx.core.engine import Guard
from rbacx.core.model import Subject, Resource, Action, Context
from rbacx.metrics.prometheus import PrometheusMetrics
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

policy = {"rules":[{"id":"doc_read","effect":"permit","actions":["read"],"resource":{"type":"doc"}}]}
metrics = PrometheusMetrics(namespace="rbacx")
guard = Guard(policy, metrics=metrics)

def build_env(request: Request):
    user = request.headers.get("x-user", "anonymous")
    return Subject(id=user, roles=["user"]), Action("read"), Resource(type="doc"), Context()

app = FastAPI()
@app.get("/ping")
def ping(): return {"pong": True}

@app.get("/docs", dependencies=[Depends(require_access(guard, build_env, add_headers=True))])
async def docs(): return {"ok": True}

@app.get("/metrics")
def metrics_endpoint():
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)
