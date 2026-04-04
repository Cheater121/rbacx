"""Factory that builds the RBACX Guard for the async Django demo.

``settings.RBACX_GUARD_FACTORY`` points here.  The middleware calls
``build_guard()`` once at startup and attaches the returned instance to
every request as ``request.rbacx_guard``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Final

from rbacx import Guard

_LOCAL_POLICY: Final[Path] = Path(__file__).with_name("policy.json")


def _load_policy() -> dict:
    if _LOCAL_POLICY.exists():
        return json.loads(_LOCAL_POLICY.read_text(encoding="utf-8"))
    # Minimal fallback so the demo runs even without a policy file.
    return {
        "algorithm": "deny-overrides",
        "rules": [
            {
                "id": "permit-read-doc",
                "effect": "permit",
                "actions": ["read"],
                "resource": {"type": "doc"},
                "roles": ["admin", "editor"],
            }
        ],
    }


def build_guard() -> Guard:
    """Construct and return the RBACX Guard (called once at startup)."""
    return Guard(_load_policy())
