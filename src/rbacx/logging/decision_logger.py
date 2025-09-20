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
        redact_in_place: bool = False,
    ) -> None:
        # Sampling: 0.0 → drop all, 1.0 → log all
        self.sample_rate = float(sample_rate)
        # Obligation specs for redaction/masking (enforcer understands their schema)
        self.redactions = redactions or []
        # Destination logger and format
        self.logger = logging.getLogger(logger_name)
        self.as_json = as_json
        self.level = level
        # Whether to mutate the original env in place (no deep copy)
        self.redact_in_place = bool(redact_in_place)

    def log(self, payload: Dict[str, Any]) -> None:
        # Probabilistic sampling
        if self.sample_rate <= 0.0 or random.random() > self.sample_rate:
            return

        # Shallow copy of the outer payload so we can safely replace `env`
        safe = dict(payload)

        # Pull env (may be missing)
        env_obj: Dict[str, Any] = dict(safe.get("env") or {})

        try:
            if self.redactions:
                # Forward the in_place flag to the enforcer:
                # - in_place=False (default): deep-copied, original `env` is untouched
                # - in_place=True: mutate original `env` (fewer copies)
                redacted_env = apply_obligations(
                    env_obj, self.redactions, in_place=self.redact_in_place
                )
            else:
                redacted_env = env_obj

            # Install the (possibly redacted) env back into the log payload
            safe["env"] = redacted_env
        except Exception:
            # Never fail logging due to redaction errors; keep an internal trace
            dbg = getattr(self.logger, "debug", None)
            if callable(dbg):
                dbg("DecisionLogger: failed to apply redactions", exc_info=True)

        # Render message
        if self.as_json:
            msg = json.dumps(safe, ensure_ascii=False)
        else:
            msg = f"decision {safe}"

        # Emit
        self.logger.log(self.level, msg)
