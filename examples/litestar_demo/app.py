from __future__ import annotations

import json
import logging
import logging.config
import os
from pathlib import Path

from litestar import Litestar, get
from litestar.di import Provide
from litestar.middleware import DefineMiddleware

from rbacx.adapters.asgi import RbacxMiddleware
from rbacx.adapters.asgi_accesslog import AccessLogMiddleware
from rbacx.adapters.asgi_logging import TraceIdMiddleware
from rbacx.core.engine import Guard
from rbacx.core.model import Action, Context, Resource, Subject
from rbacx.storage import FilePolicySource, HotReloader

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {"default": {"format": "%(asctime)s %(levelname)s %(name)s: %(message)s"}},
    "handlers": {
        "console": {"class": "logging.StreamHandler", "formatter": "default", "filters": ["trace"]}
    },
    "filters": {"trace": {"()": "rbacx.logging.context.TraceIdFilter"}},
    "root": {"level": "INFO", "handlers": ["console"]},
}
if os.getenv("RBACX_LOG_JSON") == "1":
    LOGGING["formatters"]["default"] = {
        "class": "pythonjsonlogger.jsonlogger.JsonFormatter",
        "format": "%(asctime)s %(levelname)s %(name)s %(message)s %(trace_id)s",
    }
logging.config.dictConfig(LOGGING)

policy_path = Path(__file__).with_name("policy.json")
guard = Guard(json.load(open(policy_path, "r", encoding="utf-8")))
reloader = HotReloader(guard, FilePolicySource(str(policy_path)), poll_interval=0.5)


def current_subject() -> Subject:
    return Subject(id="u1", roles=["user"], attrs={})


def current_context() -> Context:
    return Context(attrs={"mfa": True})


@get(
    "/docs/{doc_id:int}", dependencies={"rbacx_guard": Provide(lambda: guard, sync_to_thread=True)}
)
async def get_doc(doc_id: int, rbacx_guard: Guard) -> dict:
    return {
        "allowed": (
            await rbacx_guard.evaluate_async(
                current_subject(),
                Action("read"),
                Resource(type="doc", id=str(doc_id)),
                current_context(),
            )
        ).allowed
    }


app = Litestar(
    route_handlers=[get_doc],
    middleware=[
        TraceIdMiddleware,
        AccessLogMiddleware,
        DefineMiddleware(RbacxMiddleware, guard=guard),
    ],
)

# Run: uvicorn examples.litestar_demo.app:app --reload --log-config examples/logging/uvicorn_logging_json.yml


@get("/health")
async def health() -> dict:
    return {"ok": True}
