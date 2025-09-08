
from flask import Flask, request
from rbacx.adapters.flask import require_access
from rbacx.core.engine import Guard
from rbacx.core.model import Subject, Resource, Action, Context
import json, pathlib

policy = json.loads(pathlib.Path(__file__).with_name("policy.json").read_text(encoding="utf-8"))
guard = Guard(policy)

def build_env(req):
    user = (req or request).headers.get("x-user", "anonymous")
    return Subject(id=user, roles=["user"]), Action("read"), Resource(type="doc"), Context()

app = Flask(__name__)

@app.get("/ping")
def ping(): return {"pong": True}

@app.get("/docs")
@require_access(guard, build_env, add_headers=True)
def docs(): return {"ok": True}
