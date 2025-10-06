from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Decision:
    allowed: bool
    effect: str  # "permit" | "deny"
    obligations: list[dict[str, Any]] = field(default_factory=list)
    challenge: str | None = None
    rule_id: str | None = None
    policy_id: str | None = None
    reason: str | None = None
