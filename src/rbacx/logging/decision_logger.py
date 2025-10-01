from __future__ import annotations

import json
import logging
import random
from typing import Any, Dict, List, Optional

from ..core.ports import DecisionLogSink
from ..obligations.enforcer import apply_obligations

# Safe-by-default set used only when opt-in flag `use_default_redactions=True`
_DEFAULT_REDACTIONS: List[Dict[str, Any]] = [
    {
        "type": "redact_fields",
        "fields": [
            "subject.attrs.password",
            "subject.attrs.token",
            "subject.attrs.mfa_code",
            "context.headers.authorization",
            "context.cookies",
            "resource.attrs.secret",
            "subject.attrs.email",
            "subject.attrs.phone",
        ],
    },
    {"type": "mask_fields", "fields": ["context.ip"], "placeholder": "***"},
]


class DecisionLogger(DecisionLogSink):
    """
    Minimal, framework-agnostic audit logger for PDP decisions.

    Backwards-compatible defaults:
      - No redactions are applied unless explicitly configured.
      - `sample_rate` controls probabilistic logging: 0.0 → drop all, 1.0 → log all.
      - Smart sampling is disabled by default.
      - No env size limit by default.

    Opt-in features:
      - `use_default_redactions=True` enables DEFAULT_REDACTIONS when `redactions` is not provided.
      - `smart_sampling=True` enables category-aware sampling (deny and permit-with-obligations can be forced to 1.0).
      - `max_env_bytes` truncates the (redacted) env if the serialized JSON exceeds the threshold.
    """

    def __init__(
        self,
        *,
        sample_rate: float = 1.0,
        redactions: Optional[List[Dict[str, Any]]] = None,
        logger_name: str = "rbacx.audit",
        as_json: bool = False,
        level: int = logging.INFO,
        redact_in_place: bool = False,
        use_default_redactions: bool = False,  # opt-in; keeps old behavior by default
        smart_sampling: bool = False,  # opt-in; keeps old behavior by default
        category_sampling_rates: Optional[
            Dict[str, float]
        ] = None,  # e.g. {"deny":1.0,"permit_with_obligations":1.0}
        max_env_bytes: Optional[int] = None,  # opt-in size limit for serialized env
    ) -> None:
        # Sampling: 0.0 → drop all, 1.0 → log all
        self.sample_rate = float(sample_rate)

        # Keep the raw value to distinguish "not provided" vs "provided empty list"
        self._redactions_provided = redactions is not None
        self.redactions = redactions or []

        # Destination logger and format
        self.logger = logging.getLogger(logger_name)
        self.as_json = as_json
        self.level = level

        # Whether to mutate the original env in place (no deep copy)
        self.redact_in_place = bool(redact_in_place)

        # Safe defaults and smart sampling (both opt-in)
        self.use_default_redactions = bool(use_default_redactions)
        self.smart_sampling = bool(smart_sampling)
        self.sample_strategy = dict(
            category_sampling_rates or {"deny": 1.0, "permit_with_obligations": 1.0}
        )

        # Size limit (opt-in)
        self.max_env_bytes = (
            max_env_bytes if (isinstance(max_env_bytes, int) and max_env_bytes > 0) else None
        )

    def log(self, payload: Dict[str, Any]) -> None:  # type: ignore[override]
        # Category-aware sampling if enabled; otherwise legacy sampling
        if self._should_drop_by_sampling(payload):
            return

        # Shallow copy so we can replace `env` safely
        safe = dict(payload)

        # Pull env (may be missing)
        env_obj: Dict[str, Any] = dict(safe.get("env") or {})

        # Choose effective redaction set per strict priority
        if self._redactions_provided:
            redaction_specs = self.redactions
        elif self.use_default_redactions:
            redaction_specs = _DEFAULT_REDACTIONS
        else:
            redaction_specs = []

        try:
            if redaction_specs:
                redacted_env = apply_obligations(
                    env_obj, redaction_specs, in_place=self.redact_in_place
                )
            else:
                redacted_env = env_obj

            # Apply size limit check AFTER redactions (so redactions can reduce size)
            if self.max_env_bytes is not None:
                try:
                    serialized = json.dumps(redacted_env, ensure_ascii=False)
                    if len(serialized) > self.max_env_bytes:
                        safe["env"] = {"_truncated": True, "size_bytes": len(serialized)}
                    else:
                        safe["env"] = redacted_env
                except Exception:
                    # On serialization issues, fall back to original behavior
                    safe["env"] = redacted_env
            else:
                safe["env"] = redacted_env
        except Exception:
            # Never fail logging due to redaction/size errors; keep an internal trace
            dbg = getattr(self.logger, "debug", None)
            if callable(dbg):
                # Keep legacy message for compatibility with existing tests
                dbg("DecisionLogger: failed to apply redactions", exc_info=True)
            # Preserve previous behavior: emit original env as-is
            safe["env"] = env_obj

        # Render message
        if self.as_json:
            msg = json.dumps(safe, ensure_ascii=False)
        else:
            # Keep the legacy text format stable
            msg = f"decision {safe}"

        # Emit
        self.logger.log(self.level, msg)

    # ---------------------------- internals

    def _should_drop_by_sampling(self, payload: Dict[str, Any]) -> bool:
        """Return True if the record should be dropped by sampling."""
        if not self.smart_sampling:
            # Legacy single-rate sampling
            return self.sample_rate <= 0.0 or random.random() > self.sample_rate

        # Smart sampling: compute category and pick an effective rate
        decision = str(payload.get("decision", ""))
        allowed = bool(payload.get("allowed", False))
        obligations = payload.get("obligations") or []  # may be missing; treat as empty
        if decision == "deny" or not allowed:
            category = "deny"
        elif obligations:
            category = "permit_with_obligations"
        else:
            category = "permit"

        eff_rate = self.sample_strategy.get(category, self.sample_rate)
        eff_rate = max(0.0, min(1.0, float(eff_rate)))
        return eff_rate <= 0.0 or random.random() > eff_rate
