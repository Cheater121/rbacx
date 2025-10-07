from asyncio import AbstractEventLoop
from contextvars import ContextVar

from .ports import RelationshipChecker

# ReBAC provider ambiently available for the current decision
REL_CHECKER: ContextVar[RelationshipChecker | None] = ContextVar("rbacx_rel_checker", default=None)

# Per-decision memo cache: (subject, relation, resource, ctx_hash) -> bool
REL_LOCAL_CACHE: ContextVar[dict[tuple[str, str, str, str], bool] | None] = ContextVar(
    "rbacx_rel_cache", default=None
)

# Event loop captured in the outer task so policy code (running in a worker thread)
# can submit coroutines back to it via run_coroutine_threadsafe.
EVAL_LOOP: ContextVar[AbstractEventLoop | None] = ContextVar("rbacx_eval_loop", default=None)
