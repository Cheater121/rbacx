from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple


@dataclass(frozen=True)
class ObligationCheckResult:
    """Small DTO kept for backwards-compatibility if needed by contributors."""
    ok: bool
    challenge: Optional[str] = None
    reason: Optional[str] = None


class BasicObligationChecker:
    """Validate common obligations carried by a decision.

    Design goals (documented for contributors):
    - **Fail-closed** semantics preserved for legacy callers:
      * If legacy string key `decision` is present and not equal to "permit" -> `(False, None)`.
      * If legacy key absent, derive effect from `effect`/`allowed`; any non-"permit" -> `(False, None)`.
    - Support obligations targeting the *current* effect (`on: "permit" | "deny"`).
      This allows, for example, an explicit `http_challenge` on `deny` to still surface a challenge.
    - Do not mutate the incoming decision; return a `(ok, challenge)` tuple for the Guard to consume.
    - Unknown obligation `type` is ignored (treated as advice/no-op).

    Supported `type` values:
      - `require_mfa`            -> challenge "mfa"
      - `require_level`          (attrs.min)  -> "step_up"
      - `http_challenge`         (attrs.scheme in Basic/Bearer/Digest) -> "http_basic" / "http_bearer" / "http_digest"; else "http_auth"
      - `require_consent`        (attrs.key or any consent) -> "consent"
      - `require_terms_accept`   -> "tos"
      - `require_captcha`        -> "captcha"
      - `require_reauth`         (attrs.max_age vs context.reauth_age_seconds) -> "reauth"
      - `require_age_verified`   -> "age_verification"
    """

    def check(self, decision: Dict[str, Any], context: Any) -> Tuple[bool, Optional[str]]:
        """Check obligations attached to a raw decision.

        Parameters
        ----------
        decision: Mapping-like (dict). Legacy callers may pass string key `decision` ("permit"|"deny");
                  modern shape may include `effect`/`allowed`. `obligations` is a list of mappings.
        context : Object whose `.attrs` is a dict (or context itself is a dict).

        Returns
        -------
        (ok, challenge): bool and optional machine-readable challenge string.
        """
        obligations = decision.get("obligations") or []

        # If there are no obligations, preserve legacy fail-closed semantics for non-permit.
        if not obligations:
            decision_label = decision.get("decision")
            if isinstance(decision_label, str):
                return (decision_label == "permit"), None
            effect = decision.get("effect") or ("permit" if decision.get("allowed") else "deny")
            return (effect == "permit"), None

        # Determine current effect with legacy key taking precedence.
        decision_label = decision.get("decision")
        if isinstance(decision_label, str):
            current_effect = "permit" if decision_label == "permit" else "deny"
        else:
            current_effect = decision.get("effect") or ("permit" if decision.get("allowed") else "deny")

        # Baseline ok: permit -> True, deny -> False (fail-closed), but obligations may still add a challenge.
        baseline_ok = (current_effect == "permit")

        ctx = getattr(context, "attrs", context) or {}

        for ob in obligations:
            # Only apply obligations for the current effect.
            on = (ob or {}).get("on") or "permit"
            if on not in ("permit", "deny") or on != current_effect:
                continue

            typ = (ob or {}).get("type")
            attrs = (ob or {}).get("attrs") or {}

            # --- MFA ---
            if typ == "require_mfa":
                if not bool(ctx.get("mfa")):
                    return False, "mfa"

            # --- Step-up auth (numeric level) ---
            elif typ == "require_level":
                try:
                    min_level = int(attrs.get("min", 0))
                except Exception:
                    min_level = 0
                cur_level = int(ctx.get("auth_level", 0) or 0)
                if cur_level < min_level:
                    return False, "step_up"

            # --- Explicit HTTP auth challenge (PEP decides headers via WWW-Authenticate) ---
            elif typ == "http_challenge":
                scheme = str(attrs.get("scheme", "")).lower()
                if scheme in {"basic", "bearer", "digest"}:
                    return False, f"http_{scheme}"
                return False, "http_auth"

            # --- Consent ---
            elif typ == "require_consent":
                key = attrs.get("key")
                if key is None:
                    if not bool(ctx.get("consent")):
                        return False, "consent"
                else:
                    consent = ctx.get("consent") or {}
                    if not bool(consent.get(key)):
                        return False, "consent"

            # --- Terms of Service ---
            elif typ == "require_terms_accept":
                if not bool(ctx.get("tos_accepted")):
                    return False, "tos"

            # --- CAPTCHA ---
            elif typ == "require_captcha":
                if not bool(ctx.get("captcha_passed")):
                    return False, "captcha"

            # --- Reauthentication freshness ---
            elif typ == "require_reauth":
                try:
                    max_age = int(attrs.get("max_age", 0))
                except Exception:
                    max_age = 0
                reauth_age = int(ctx.get("reauth_age_seconds", 0) or 0)
                if reauth_age > max_age:
                    return False, "reauth"

            # --- Age verification ---
            elif typ == "require_age_verified":
                if not bool(ctx.get("age_verified")):
                    return False, "age_verification"

            # Unknown types are ignored (treated as advice).

        return baseline_ok, None
