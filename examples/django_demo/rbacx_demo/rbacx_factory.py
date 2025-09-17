"""
Factory that builds a real RBACX Guard for the Django demo.

This file intentionally stays small: the Django adapter (middleware)
is responsible for wiring the guard into request/response handling.
We only construct the Guard here and let the middleware do the rest.

settings.RBACX_GUARD_FACTORY should point to: "rbacx_demo.rbacx_factory.build_guard".
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Final

from rbacx.core.engine import Guard

# Default relative policy locations (local override first, then shared demo)
_LOCAL_POLICY: Final[Path] = Path(__file__).with_name("policy.json")
_SHARED_POLICY: Final[Path] = Path(__file__).resolve().parents[2] / "policies" / "ok_policy.json"


def _load_policy() -> dict:
    """
    Load a demo policy for the Guard.

    Priority:
      1) ./policy.json (next to this file)
      2) ../../policies/ok_policy.json (shared policy for all demos)

    If neither exists, fall back to a minimal permissive policy that
    demonstrates a successful 'read' decision for resource type 'doc'.
    """
    policy_path = _LOCAL_POLICY if _LOCAL_POLICY.exists() else _SHARED_POLICY
    if policy_path.exists():
        return json.loads(policy_path.read_text(encoding="utf-8"))

    # Fallback: keep the demo usable even without policy files around.
    return {
        "algorithm": "permit-overrides",
        "rules": [
            {
                "id": "fallback-permit-read-doc",
                "effect": "permit",
                "actions": ["read"],
                "resource": {"type": "doc"},
            }
        ],
    }


def build_guard() -> Guard:
    """
    Construct and return the RBACX Guard.

    The Django adapter middleware will:
      - obtain this guard via settings.RBACX_GUARD_FACTORY,
      - attach it to incoming requests (e.g., request.rbacx_guard),
      - optionally add explanation headers on deny (if enabled in settings).
    """
    policy = _load_policy()
    return Guard(policy)
