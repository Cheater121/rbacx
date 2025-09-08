
from __future__ import annotations

import logging
import random
from typing import Any, Dict, List

from ..obligations.enforcer import apply_obligations


class DecisionLogger:
    def __init__(self, *, sample_rate: float = 1.0, redactions: List[Dict[str, Any]] | None = None, logger_name: str = "rbacx.audit") -> None:
        self.sample_rate = float(sample_rate)
        self.redactions = redactions or []
        self.logger = logging.getLogger(logger_name)

    def log(self, payload: Dict[str, Any]) -> None:
        if self.sample_rate <= 0.0:
            return
        if random.random() > self.sample_rate:
            return
        safe = dict(payload)
        env = safe.get("env") or {}
        # apply obligations to env copy if configured
        try:
            if self.redactions:
                safe["env"] = apply_obligations(env, self.redactions)  # type: ignore[arg-type]
        except Exception:  # pragma: no cover
            pass
        self.logger.info("decision %s", safe)
