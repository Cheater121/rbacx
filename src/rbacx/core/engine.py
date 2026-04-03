import asyncio
import hashlib
import inspect
import json
import logging
import threading
import time
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from typing import Any, ClassVar

from .cache import AbstractCache
from .decision import Decision, RuleTrace
from .helpers import maybe_await
from .model import Action, Context, Resource, Subject
from .obligations import BasicObligationChecker
from .policy import decide as decide_policy
from .policyset import decide as decide_policyset
from .ports import (
    DecisionLogSink,
    MetricsSink,
    ObligationChecker,
    RelationshipChecker,
    RoleResolver,
)
from .relctx import EVAL_LOOP, REL_CHECKER, REL_LOCAL_CACHE

try:
    # optional compile step to speed up decision making
    from .compiler import compile as compile_policy
except Exception:  # pragma: no cover - compiler is optional
    compile_policy = None  # type: ignore[assignment]

logger = logging.getLogger("rbacx.engine")


def _now() -> float:
    """Monotonic time for durations."""
    return time.perf_counter()


class Guard:
    """Policy evaluation engine.

    Holds a policy or a policy set and evaluates access decisions.

    Design:
      - Single async core `_evaluate_core_async` (one source of truth).
      - Sync API wraps the async core; if a loop is already running, uses a
        class-level ThreadPoolExecutor (created lazily, shared across all Guard
        instances) to avoid the overhead of spawning a new thread pool on every
        call.
      - DI (resolver/obligations/metrics/logger) can be sync or async; both supported via `maybe_await`.
      - CPU-bound evaluation is offloaded to a thread via `asyncio.to_thread`.
    """

    # Shared executor for evaluate_sync() when called from a running event loop.
    # Created lazily on first use; one thread is sufficient because each submitted
    # coroutine runs its own asyncio.run() and does not block the worker thread
    # while awaiting I/O.
    _executor: ClassVar[ThreadPoolExecutor | None] = None

    def __init__(
        self,
        policy: dict[str, Any],
        *,
        logger_sink: DecisionLogSink | None = None,
        metrics: MetricsSink | None = None,
        obligation_checker: ObligationChecker | None = None,
        role_resolver: RoleResolver | None = None,
        relationship_checker: RelationshipChecker | None = None,
        cache: AbstractCache | None = None,
        cache_ttl: int | None = 300,
        strict_types: bool = False,
    ) -> None:
        self.policy: dict[str, Any] = policy
        self.logger_sink = logger_sink
        self.metrics = metrics
        self.obligations: ObligationChecker = obligation_checker or BasicObligationChecker()
        self.role_resolver = role_resolver
        # Optional decision cache (per-Guard instance by default)
        self.cache: AbstractCache | None = cache
        self.cache_ttl: int | None = cache_ttl
        self.policy_etag: str | None = None
        self._compiled: Callable[[dict[str, Any]], dict[str, Any]] | None = None
        self.strict_types: bool = bool(strict_types)
        self.relationship_checker = relationship_checker
        # Guards atomic replacement of policy / etag / compiled function.
        # RLock allows re-entrant acquisition: set_policy -> _recompute_etag -> clear_cache
        # can all hold the lock in the same thread without deadlocking.
        self._policy_lock: threading.RLock = threading.RLock()

        self._recompute_etag()

    # ---------------------------------------------------------------- set/update

    def set_policy(self, policy: dict[str, Any]) -> None:
        """Replace policy/policyset.

        Thread-safe: acquires ``_policy_lock`` so that concurrent readers in
        ``_decide_async`` always see a consistent triple of
        ``(policy, policy_etag, _compiled)``.
        """
        with self._policy_lock:
            self.policy = policy
            self._recompute_etag()
            # Invalidate cache entirely; etag changes will naturally change keys,
            # but clearing avoids memory growth and stale entries.
            self.clear_cache()

    def update_policy(self, policy: dict[str, Any]) -> None:
        """Alias kept for backward-compatibility."""
        self.set_policy(policy)

    # ------------------------------ caching helpers

    @staticmethod
    def _normalize_env_for_cache(env: dict[str, Any]) -> str:
        """Return a deterministic JSON string for cache key construction.

        - sort_keys=True ensures a stable order
        - separators reduce size
        - default=str avoids TypeErrors for non-JSON types by stringifying them.
        - ensure_ascii=False preserves unicode while keeping key stable
        Security: Do NOT put secrets into keys for shared caches. The default
        in-memory cache is per-process and per-Guard; for external caches,
        ensure transport-level protections.
        """
        try:
            return json.dumps(
                env, sort_keys=True, separators=(",", ":"), default=str, ensure_ascii=False
            )
        except Exception:
            # As a last resort, fall back to repr which is deterministic for basic containers.
            return repr(env)

    def _cache_key(self, env: dict[str, Any]) -> str | None:
        etag = getattr(self, "policy_etag", None)
        if not etag:
            return None
        return f"{etag}:{self._normalize_env_for_cache(env)}"

    # ---------------------------------------------------------------- decision core (async only)

    async def _decide_async(self, env: dict[str, Any]) -> dict[str, Any]:
        """
        Async decision that keeps the event loop responsive:
        compiled/policy/policyset functions are sync -> offload via to_thread.

        When ``__explain__`` is set in *env* the compiled fast-path is skipped:
        the compiler pre-filters rules by action/resource-type before handing
        them to the interpreter, so action- or resource-mismatched rules would
        never be seen and could not appear in the trace.  The uncompiled path
        passes *all* rules to ``evaluate_policy`` which records every skip.
        """
        fn = self._compiled
        loop = asyncio.get_running_loop()
        token = EVAL_LOOP.set(loop)
        try:
            # compiled fast-path — bypassed when explain mode is active so that
            # every rule (including skipped ones) appears in Decision.trace.
            if fn is not None and not env.get("__explain__"):
                try:
                    return await asyncio.to_thread(fn, env)
                except Exception:  # pragma: no cover
                    logger.exception("RBACX: compiled decision failed; falling back")

            # policyset vs single policy
            if "policies" in self.policy:
                return await asyncio.to_thread(decide_policyset, self.policy, env)

            return await asyncio.to_thread(decide_policy, self.policy, env)
        finally:
            EVAL_LOOP.reset(token)

    # ---------------------------------------------------------------- evaluation core (single source of truth)

    async def _evaluate_core_async(
        self,
        subject: Subject,
        action: Action,
        resource: Resource,
        context: Context | None,
        *,
        explain: bool = False,
    ) -> Decision:
        start = _now()

        # Build env (resolver may be sync or async)
        roles: list[str] = list(subject.roles or [])
        if self.role_resolver is not None:
            try:
                roles = await maybe_await(self.role_resolver.expand(roles))
            except Exception:
                logger.exception("RBACX: role resolver failed", exc_info=True)
        env: dict[str, Any] = {
            "subject": {"id": subject.id, "roles": roles, "attrs": dict(subject.attrs or {})},
            "action": action.name,
            "resource": {
                "type": resource.type,
                "id": resource.id,
                "attrs": dict(resource.attrs or {}),
            },
            "context": dict(getattr(context, "attrs", {}) or {}),
        }

        if self.strict_types:
            env["__strict_types__"] = True

        if explain:
            env["__explain__"] = True

        raw = None
        cache = getattr(self, "cache", None)
        key: str | None = None

        if cache is not None:
            try:
                key = self._cache_key(env)
                if key:
                    cached = cache.get(key)
                    if cached is not None:
                        raw = cached
            except Exception:  # pragma: no cover
                logger.exception("RBACX: cache.get failed")

        if raw is None:
            # Make ReBAC provider and a per-decision local cache available to policy code
            _t1 = REL_CHECKER.set(self.relationship_checker)
            _t2 = REL_LOCAL_CACHE.set({})
            try:
                raw = await self._decide_async(env)
            finally:
                REL_CHECKER.reset(_t1)
                REL_LOCAL_CACHE.reset(_t2)

            if cache is not None:
                try:
                    if key:
                        cache.set(key, raw, ttl=self.cache_ttl)
                except Exception:  # pragma: no cover
                    logger.exception("RBACX: cache.set failed")

        # determine effect/allowed with obligations
        decision_str = str(raw.get("decision"))
        effect = "permit" if decision_str == "permit" else "deny"
        obligations_list = list(raw.get("obligations") or [])
        challenge = raw.get("challenge")
        allowed = decision_str == "permit"
        # Local variable for reason — never mutate raw (it may be a cached object).
        reason = raw.get("reason")

        if allowed:
            try:
                # Pass the full evaluation env to the checker so that obligation
                # conditions (``condition`` field) can reference subject / resource /
                # action / context attributes via eval_condition.
                # We shallow-copy raw to avoid mutating the (possibly cached) object.
                raw_for_checker: dict[str, Any] = {**raw, "__env__": env}
                ok, ch = await maybe_await(self.obligations.check(raw_for_checker, context))
                allowed = bool(ok)
                if ch is not None:
                    challenge = ch
                # Auto-deny when an obligation is not met
                if not allowed:
                    effect = "deny"
                    reason = "obligation_failed"
            except Exception:
                # do not fail on obligation checker errors
                logger.exception("RBACX: obligation checker failed", exc_info=True)

        # Build trace: convert raw dicts to RuleTrace objects when present.
        raw_trace = raw.get("trace")
        trace: list[RuleTrace] | None = None
        if isinstance(raw_trace, list):
            trace = [
                RuleTrace(
                    rule_id=str(t.get("rule_id") or ""),
                    effect=str(t.get("effect") or "deny"),
                    matched=bool(t.get("matched")),
                    skip_reason=t.get("skip_reason") or None,
                )
                for t in raw_trace
                if isinstance(t, dict)
            ]

        d = Decision(
            allowed=allowed,
            effect=effect,
            obligations=obligations_list,
            challenge=challenge,
            rule_id=raw.get("last_rule_id") or raw.get("rule_id"),
            policy_id=raw.get("policy_id"),
            reason=reason,
            trace=trace,
        )

        # metrics (do not use return values; conditionally await)
        if self.metrics is not None:
            labels = {"decision": d.effect}
            try:
                inc = getattr(self.metrics, "inc", None)
                if inc is not None:
                    if inspect.iscoroutinefunction(inc):
                        await inc("rbacx_decisions_total", labels)
                    else:
                        inc("rbacx_decisions_total", labels)
            except Exception:  # pragma: no cover
                logger.exception("RBACX: metrics.inc failed")
            try:
                observe = getattr(self.metrics, "observe", None)
                if observe is not None:
                    dur = max(0.0, _now() - start)
                    if inspect.iscoroutinefunction(observe):
                        await observe("rbacx_decision_seconds", dur, labels)
                    else:
                        observe("rbacx_decision_seconds", dur, labels)
            except Exception:  # pragma: no cover
                logger.exception("RBACX: metrics.observe failed")

        # logging (do not use return value; conditionally await)
        if self.logger_sink is not None:
            try:
                log = getattr(self.logger_sink, "log", None)
                if log is not None:
                    payload = {
                        "env": env,
                        "decision": d.effect,
                        "allowed": d.allowed,
                        "rule_id": d.rule_id,
                        "policy_id": d.policy_id,
                        "reason": d.reason,
                        "obligations": d.obligations,
                    }
                    if inspect.iscoroutinefunction(log):
                        await log(payload)
                    else:
                        log(payload)
            except Exception:  # pragma: no cover
                logger.exception("RBACX: decision logging failed")

        return d

    # ---------------------------------------------------------------- public APIs

    def clear_cache(self) -> None:
        """Clear the decision cache if configured.

        This is safe to call at any time. Errors are swallowed to avoid
        interfering with decision flow.
        """
        cache = getattr(self, "cache", None)
        if cache is not None:
            try:
                cache.clear()
            except Exception:  # pragma: no cover
                logger.exception("RBACX: cache.clear() failed")

    def evaluate_sync(
        self,
        subject: Subject,
        action: Action,
        resource: Resource,
        context: Context | None = None,
        *,
        explain: bool = False,
    ) -> Decision:
        """Synchronous wrapper for the async core.

        - If no running loop in this thread: use asyncio.run() directly.
        - If a loop is running (e.g. called from sync code inside an async
          framework): submit to the class-level ThreadPoolExecutor so the
          worker thread gets its own event loop via asyncio.run().  The
          executor is created lazily and reused across calls to avoid the
          overhead of spawning a new thread pool on every invocation.

        Args:
            explain: when ``True``, populate :attr:`Decision.trace` with a
                per-rule evaluation log.  Has no effect on the decision itself.
        """
        try:
            asyncio.get_running_loop()
            loop_running = True
        except RuntimeError:
            loop_running = False

        if not loop_running:
            return asyncio.run(
                self._evaluate_core_async(subject, action, resource, context, explain=explain)
            )

        # Avoid interacting with the already running loop from sync code.
        def _runner() -> Decision:
            return asyncio.run(
                self._evaluate_core_async(subject, action, resource, context, explain=explain)
            )

        if Guard._executor is None:
            Guard._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="rbacx-sync")
        fut = Guard._executor.submit(_runner)
        return fut.result()

    async def evaluate_async(
        self,
        subject: Subject,
        action: Action,
        resource: Resource,
        context: Context | None = None,
        *,
        explain: bool = False,
    ) -> Decision:
        """True async API for ASGI frameworks.

        Args:
            explain: when ``True``, populate :attr:`Decision.trace` with a
                per-rule evaluation log.  Has no effect on the decision itself.
        """
        return await self._evaluate_core_async(subject, action, resource, context, explain=explain)

    # ---------------------------------------------------------------- batch APIs

    async def evaluate_batch_async(
        self,
        requests: Sequence[tuple[Subject, Action, Resource, Context | None]],
        *,
        explain: bool = False,
    ) -> list[Decision]:
        """Evaluate multiple access requests concurrently, preserving order.

        Runs all requests in parallel via :func:`asyncio.gather`.  The
        returned list has exactly one :class:`Decision` per input tuple, in
        the same order.  If any individual evaluation raises an exception the
        whole batch propagates that exception (fail-fast semantics).

        Args:
            requests: sequence of ``(subject, action, resource, context)``
                tuples.  *context* may be ``None``.
            explain: when ``True``, populate :attr:`Decision.trace` on every
                returned :class:`Decision`.

        Returns:
            List of :class:`Decision` objects, one per request, preserving
            input order.

        Example::

            decisions = await guard.evaluate_batch_async([
                (subject, Action("read"),   resource1, ctx),
                (subject, Action("write"),  resource1, ctx),
                (subject, Action("delete"), resource2, None),
            ])
        """
        if not requests:
            return []
        return list(
            await asyncio.gather(
                *[self._evaluate_core_async(s, a, r, c, explain=explain) for s, a, r, c in requests]
            )
        )

    def evaluate_batch_sync(
        self,
        requests: Sequence[tuple[Subject, Action, Resource, Context | None]],
        *,
        explain: bool = False,
    ) -> list[Decision]:
        """Synchronous wrapper for :meth:`evaluate_batch_async`.

        Uses the same loop-detection strategy as :meth:`evaluate_sync`: runs
        directly via :func:`asyncio.run` when no event loop is active, or
        submits to the class-level :class:`~concurrent.futures.ThreadPoolExecutor`
        when called from within a running loop.

        Args:
            requests: sequence of ``(subject, action, resource, context)``
                tuples.  *context* may be ``None``.
            explain: when ``True``, populate :attr:`Decision.trace` on every
                returned :class:`Decision`.

        Returns:
            List of :class:`Decision` objects, one per request, preserving
            input order.
        """
        if not requests:
            return []

        try:
            asyncio.get_running_loop()
            loop_running = True
        except RuntimeError:
            loop_running = False

        if not loop_running:
            return asyncio.run(self.evaluate_batch_async(requests, explain=explain))

        def _runner() -> list[Decision]:
            return asyncio.run(self.evaluate_batch_async(requests, explain=explain))

        if Guard._executor is None:
            Guard._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="rbacx-sync")
        fut = Guard._executor.submit(_runner)
        return fut.result()

    # convenience

    def is_allowed_sync(
        self, subject: Subject, action: Action, resource: Resource, context: Context | None = None
    ) -> bool:
        d = self.evaluate_sync(subject, action, resource, context)
        return d.allowed

    async def is_allowed_async(
        self, subject: Subject, action: Action, resource: Resource, context: Context | None = None
    ) -> bool:
        d = await self.evaluate_async(subject, action, resource, context)
        return d.allowed

    # ---------------------------------------------------------------- internals

    def _recompute_etag(self) -> None:
        """Recompute ``policy_etag`` and ``_compiled`` atomically under ``_policy_lock``.

        Must be called while the caller already holds ``_policy_lock`` (re-entrant),
        or during ``__init__`` before the instance is shared across threads.
        """
        with self._policy_lock:
            try:
                raw = json.dumps(self.policy, sort_keys=True).encode("utf-8")
                self.policy_etag = hashlib.sha3_256(raw).hexdigest()
            except Exception:
                self.policy_etag = None
            # compile if compiler available
            try:
                if compile_policy is not None:
                    self._compiled = compile_policy(self.policy)
            except Exception:
                self._compiled = None
