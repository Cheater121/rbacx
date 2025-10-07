from asyncio import AbstractEventLoop
from contextvars import ContextVar

from .ports import RelationshipChecker

REL_CHECKER: ContextVar[RelationshipChecker | None] = ContextVar("rbacx_rel_checker", default=None)

REL_LOCAL_CACHE: ContextVar[dict[tuple[str, str, str, str], bool] | None] = ContextVar(
    "rbacx_rel_cache", default=None
)

EVAL_LOOP: ContextVar[AbstractEventLoop | None] = ContextVar("rbacx_eval_loop", default=None)
