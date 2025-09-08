from __future__ import annotations

import hashlib
import json
import logging
import time
from typing import Any, Callable, Dict, List, Optional

from .decision import Decision
from .model import Action, Context, Resource, Subject
from .obligations import BasicObligationChecker
from .policy import decide as decide_policy
from .policyset import decide as decide_policyset
from .ports import DecisionLogger, MetricsSink, ObligationChecker, RoleResolver

try:
    # optional compile step to speed up decision making
    from .compiler import compile as compile_policy  # type: ignore[attr-defined]
except Exception:  # pragma: no cover - compiler is optional
    compile_policy = None  # type: ignore[assignment]

logger = logging.getLogger("rbacx.engine")


class Guard:
    """Policy evaluation engine.

    Holds a policy or a policy set and evaluates access decisions.
    """

    def __init__(
        self,
        policy: Dict[str, Any],
        *,
        logger_sink: DecisionLogger | None = None,
        metrics: MetricsSink | None = None,
        obligation_checker: ObligationChecker | None = None,
        role_resolver: RoleResolver | None = None,
    ) -> None:
        self.policy: Dict[str, Any] = policy
        self.logger_sink = logger_sink
        self.metrics = metrics
        self.obligations: ObligationChecker = obligation_checker or BasicObligationChecker()
        self.role_resolver = role_resolver
        self.policy_etag: Optional[str] = None
        self._compiled: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None
        self._recompute_etag()

    # ---------------------------------------------------------------- set/update

    def set_policy(self, policy: Dict[str, Any]) -> None:
        """Replace policy/policyset."""
        self.policy = policy
        self._recompute_etag()

    def update_policy(self, policy: Dict[str, Any]) -> None:
        """Alias kept for backward-compatibility."""
        self.set_policy(policy)

    # ---------------------------------------------------------------- env

    def _make_env(
        self,
        subject: Subject,
        action: Action,
        resource: Resource,
        context: Context | None,
    ) -> Dict[str, Any]:
        # Expand roles if resolver provided
        roles: List[str] = list(subject.roles or [])
        if self.role_resolver is not None:
            try:
                roles = self.role_resolver.expand(roles)
            except Exception:  # pragma: no cover
                logger.exception("RBACX: role resolver failed")
        env: Dict[str, Any] = {
            "subject": {"id": subject.id, "roles": roles, "attrs": dict(subject.attrs or {})},
            "action": action.name,
            "resource": {
                "type": resource.type,
                "id": resource.id,
                "attrs": dict(resource.attrs or {}),
            },
            "context": dict(getattr(context, "attrs", {}) or {}),
        }
        return env

    def _decide(self, env: Dict[str, Any]) -> Dict[str, Any]:
        # Use compiled function if available and matches shape
        fn = self._compiled
        try:
            if fn is not None:
                return fn(env)
        except Exception:  # pragma: no cover
            logger.exception("RBACX: compiled decision failed; falling back")
        if "policies" in self.policy:
            return decide_policyset(self.policy, env)
        return decide_policy(self.policy, env)

    # ---------------------------------------------------------------- evaluate

    def evaluate_sync(
        self,
        subject: Subject,
        action: Action,
        resource: Resource,
        context: Context | None = None,
    ) -> Decision:
        start = time.time()
        env = self._make_env(subject, action, resource, context)

        raw = self._decide(env)

        # determine effect/allowed with obligations
        decision_str = str(raw.get("decision"))
        effect = "permit" if decision_str == "permit" else "deny"
        obligations_list = list(raw.get("obligations") or [])
        challenge = raw.get("challenge")
        allowed = decision_str == "permit"
        if allowed:
            try:
                ok, ch = self.obligations.check(raw, context)
                allowed = bool(ok)
                if ch is not None:
                    challenge = ch
            except Exception:
                # do not fail on obligation checker errors
                pass

        d = Decision(
            allowed=allowed,
            effect=effect,
            obligations=obligations_list,
            challenge=challenge,
            rule_id=raw.get("last_rule_id") or raw.get("rule_id"),
            policy_id=raw.get("policy_id"),
            reason=raw.get("reason"),
        )

        # metrics
        if self.metrics is not None:
            labels = {"decision": d.effect}
            try:
                self.metrics.inc("rbacx_decisions_total", labels)
            except Exception:  # pragma: no cover
                logger.exception("RBACX: metrics.inc failed")
            try:
                # observe duration if sink supports it
                if hasattr(self.metrics, "observe"):
                    # typed as Protocol; adapter will check dynamically
                    self.metrics.observe(  # type: ignore[attr-defined]
                        "rbacx_decision_seconds",
                        max(0.0, time.time() - start),
                        labels,
                    )
            except Exception:  # pragma: no cover
                logger.exception("RBACX: metrics.observe failed")

        # logging
        if self.logger_sink is not None:
            try:
                self.logger_sink.log(
                    {
                        "subject": env.get("subject"),
                        "action": env.get("action"),
                        "resource": env.get("resource"),
                        "context": env.get("context"),
                        "decision": d.effect,
                        "allowed": d.allowed,
                        "rule_id": d.rule_id,
                        "policy_id": d.policy_id,
                        "reason": d.reason,
                    }
                )
            except Exception:  # pragma: no cover
                logger.exception("RBACX: decision logging failed")
        return d

    async def evaluate_async(
        self,
        subject: Subject,
        action: Action,
        resource: Resource,
        context: Context | None = None,
    ) -> Decision:
        # current implementation is sync; keep async signature for frameworks
        return self.evaluate_sync(subject, action, resource, context)

    # convenience

    def is_allowed_sync(self, subject: Subject, action: Action, resource: Resource, context: Context | None = None) -> bool:
        d = self.evaluate_sync(subject, action, resource, context)
        return d.allowed

    async def is_allowed_async(self, subject: Subject, action: Action, resource: Resource, context: Context | None = None) -> bool:
        d = await self.evaluate_async(subject, action, resource, context)
        return d.allowed

    # ---------------------------------------------------------------- internals

    def _recompute_etag(self) -> None:
        try:
            raw = json.dumps(self.policy, sort_keys=True).encode("utf-8")
            self.policy_etag = hashlib.sha256(raw).hexdigest()
        except Exception:
            self.policy_etag = None
        # compile if compiler available
        try:
            if compile_policy is not None:
                self._compiled = compile_policy(self.policy)  # type: ignore[misc]
        except Exception:
            self._compiled = None
