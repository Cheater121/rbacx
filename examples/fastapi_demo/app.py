import json
import pathlib

from fastapi import Depends, FastAPI, Request

from rbacx import Action, Context, Guard, Resource, Subject
from rbacx.adapters.fastapi import require_access

policy = json.loads(pathlib.Path(__file__).with_name("policy.json").read_text(encoding="utf-8"))
guard = Guard(policy)


def build_env(request: Request):
    user = request.headers.get("x-user", "anonymous")
    return Subject(id=user, roles=["user"]), Action("read"), Resource(type="doc"), Context()


app = FastAPI()
app.get("/ping")(lambda: {"pong": True})


@app.get("/doc", dependencies=[Depends(require_access(guard, build_env, add_headers=True))])
async def docs():
    return {"ok": True}
