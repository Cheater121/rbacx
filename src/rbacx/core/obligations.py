
from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from .ports import ObligationChecker


class BasicObligationChecker(ObligationChecker):
    def check(self, result: Dict[str, Any], context: Any) -> Tuple[bool, Optional[str]]:
        if (result or {}).get("decision") != "permit":
            return False, None
        obs = (result or {}).get("obligations") or []
        ctx = getattr(context, "attrs", {}) if context is not None else {}
        for ob in obs:
            if ob.get("type") == "require_mfa" and not bool(ctx.get("mfa")):
                return False, "mfa"
        return True, None
