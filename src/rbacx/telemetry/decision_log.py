
from __future__ import annotations

import json
import logging
import sys
from typing import Any, Dict

from ..core.ports import DecisionLogger

logger = logging.getLogger("rbacx.telemetry")

class StdoutDecisionLogger(DecisionLogger):
    def log(self, payload: Dict[str, Any]) -> None:
        try:
            sys.stdout.write(json.dumps(payload, ensure_ascii=False) + "\n")
        except Exception as e:
            logger.exception("RBACX: decision log failed", exc_info=e)
