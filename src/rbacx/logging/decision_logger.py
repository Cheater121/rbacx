from __future__ import annotations

import json
import logging
import random
from typing import Any, Dict, List

from ..core.ports import DecisionLogSink
from ..obligations.enforcer import apply_obligations


class DecisionLogger(DecisionLogSink):
    def __init__(
        self,
        *,
        sample_rate: float = 1.0,
        redactions: List[Dict[str, Any]] | None = None,
        logger_name: str = "rbacx.audit",
        as_json: bool = False,
        level: int = logging.INFO,
    ) -> None:
        self.sample_rate = float(sample_rate)
        self.redactions = redactions or []
        self.logger = logging.getLogger(logger_name)
        self.as_json = as_json
        self.level = level

    def log(self, payload: Dict[str, Any]) -> None:
        if self.sample_rate <= 0.0 or random.random() > self.sample_rate:
            return

        safe = dict(payload)
        env = dict(safe.get("env") or {})
        try:
            if self.redactions:
                env = apply_obligations(env, self.redactions)
            safe["env"] = env
        except Exception:
            dbg = getattr(self.logger, "debug", None)
            if callable(dbg):
                dbg("DecisionLogger: failed to apply redactions", exc_info=True)

        if self.as_json:
            msg = json.dumps(safe, ensure_ascii=False)
        else:
            msg = f"decision {safe}"

        self.logger.log(self.level, msg)
