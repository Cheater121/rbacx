
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class Decision:
    allowed: bool
    effect: str              # "permit" | "deny"
    obligations: List[Dict[str, Any]] = field(default_factory=list)
    challenge: Optional[str] = None
    rule_id: Optional[str] = None
    policy_id: Optional[str] = None
    reason: Optional[str] = None
