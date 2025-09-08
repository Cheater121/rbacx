
from __future__ import annotations

import json
import logging, logging.config, os
from litestar import Litestar, get
from litestar.di import Provide
from rbacx.adapters.litestar import make_rbacx_middleware, provide_guard
from rbacx.adapters.asgi_logging import TraceIdMiddleware
from rbacx.adapters.asgi_accesslog import AccessLogMiddleware
from rbacx.core.engine import Guard
from rbacx.core.model import Subject, Resource, Action, Context
from rbacx.storage import FilePolicySource, HotReloader
from pathlib import Path

LOGGING = {
  "version": 1, "disable_existing_loggers": False,
  "formatters": {"default": {"format": "%(asctime)s %(levelname)s %(name)s: %(message)s"}},
  "handlers": {"console": {"class": "logging.StreamHandler", "formatter": "default", "filters": ["trace"]}},
  "filters": {"trace": {"()": "rbacx.logging.context.TraceIdFilter"}},
  "root": {"level": "INFO", "handlers": ["console"]},
}
if os.getenv("RBACX_LOG_JSON") == "1":
    LOGGING["formatters"]["default"] = {
        "class": "pythonjsonlogger.jsonlogger.JsonFormatter",
        "format": "%(asctime)s %(levelname)s %(name)s %(message)s %(trace_id)s"
    }
logging.config.dictConfig(LOGGING)

policy_path = Path(__file__).with_name("policy.json")
guard = Guard(json.load(open(policy_path, "r", encoding="utf-8")))
reloader = HotReloader(guard, FilePolicySource(str(policy_path)), poll_interval=0.5)

def current_subject() -> Subject: return Subject(id="u1", roles=["user"], attrs={})
def current_context() -> Context: return Context(attrs={"mfa": True})

@get("/docs/{doc_id:int}", dependencies={"rbacx_guard": Provide(provide_guard(guard))})
def get_doc(doc_id: int, rbacx_guard: Guard) -> dict:
    return {"allowed": rbacx_guard.is_allowed_sync(current_subject(), Action("read"), Resource(type="doc", id=str(doc_id)), current_context())}

app = Litestar(route_handlers=[get_doc], middleware=[TraceIdMiddleware, AccessLogMiddleware, make_rbacx_middleware(guard, policy_reloader=reloader)])

# Run: uvicorn examples.litestar_demo.app:app --reload --log-config examples/logging/uvicorn_logging_json.yml


@get("/health")
def health() -> dict:
    return {"ok": True}
