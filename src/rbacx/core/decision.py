from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class RuleTrace:
    """Evaluation trace entry for a single rule.

    Populated in :class:`Decision.trace` when ``explain=True`` is passed to
    :meth:`~rbacx.core.engine.Guard.evaluate_sync` or
    :meth:`~rbacx.core.engine.Guard.evaluate_async`.

    Attributes:
        rule_id: the ``id`` field of the rule as declared in the policy.
        effect: declared effect of the rule — ``"permit"`` or ``"deny"``.
        matched: ``True`` if the rule fully matched (action, resource, and
            condition all passed); ``False`` if the rule was skipped.
        skip_reason: human-readable reason the rule was skipped, or ``None``
            when ``matched=True``.  Possible values mirror the ``reason``
            field of :class:`Decision`:
            ``"action_mismatch"``, ``"resource_mismatch"``,
            ``"condition_mismatch"``, ``"condition_type_mismatch"``,
            ``"condition_depth_exceeded"``.
    """

    rule_id: str
    effect: str  # "permit" | "deny"
    matched: bool
    skip_reason: str | None = None  # None when matched=True


@dataclass(frozen=True)
class Decision:
    allowed: bool
    effect: str  # "permit" | "deny"
    obligations: list[dict[str, Any]] = field(default_factory=list)
    challenge: str | None = None
    rule_id: str | None = None
    policy_id: str | None = None
    reason: str | None = None
    trace: list[RuleTrace] | None = None
