#!/usr/bin/env python3
"""
DecisionLogger configuration demo.

Run:
  python examples/logging/decision_logger_demo.py

This script shows:
  1) Legacy behavior (no redactions, single-rate sampling)
  2) Opt-in default redactions
  3) Smart sampling (category-aware)
  4) Env size limit applied AFTER redactions

It emits JSON lines to stdout via the 'rbacx.audit' logger.
"""

import logging
from typing import Any, Dict

from rbacx import Action, Context, Guard, Resource, Subject
from rbacx.logging.decision_logger import DecisionLogger


def setup_logging() -> None:
    """Configure logging so 'rbacx.audit' emits to stdout."""
    root = logging.getLogger()
    if not root.handlers:
        h = logging.StreamHandler()
        h.setFormatter(logging.Formatter("%(message)s"))
        root.addHandler(h)
    root.setLevel(logging.INFO)


def make_policy() -> Dict[str, Any]:
    """Small policy: PERMIT read when not archived, DENY delete always."""
    return {
        "algorithm": "deny-overrides",
        "rules": [
            {
                "id": "doc_read",
                "effect": "permit",
                "actions": ["read"],
                "resource": {"type": "doc", "attrs": {"archived": False}},
            },
            {
                "id": "doc_delete",
                "effect": "deny",
                "actions": ["delete"],
                "resource": {"type": "doc"},
            },
        ],
    }


def run_guard(guard: Guard) -> None:
    """Fire a PERMIT and a DENY to demonstrate logging."""
    subj = Subject(
        id="u1",
        roles=["user"],
        attrs={"email": "user@example.com", "token": "t-123", "password": "p"},
    )
    res = Resource(type="doc", id="42", attrs={"archived": False, "secret": "s"})
    ctx = Context(
        attrs={
            "ip": "10.0.0.5",
            "headers": {"authorization": "Bearer abc"},
            "cookies": {"sid": "C"},
        }
    )

    # PERMIT (read)
    _ = guard.evaluate_sync(subj, Action("read"), res, ctx)
    # DENY (delete)
    _ = guard.evaluate_sync(subj, Action("delete"), res, ctx)


def main() -> None:
    setup_logging()
    policy = make_policy()

    print("\n=== 1) Legacy behavior (no redactions, single-rate sampling) ===")
    audit_legacy = DecisionLogger(
        as_json=True,  # JSON lines
        sample_rate=1.0,  # log everything
        use_default_redactions=False,  # keep legacy behavior
    )
    guard1 = Guard(policy=policy, logger_sink=audit_legacy)
    run_guard(guard1)

    print("\n=== 2) Opt-in default redactions (uses enforcer) ===")
    audit_defaults = DecisionLogger(
        as_json=True,
        use_default_redactions=True,  # applies default redaction set when `redactions` not provided
    )
    guard2 = Guard(policy=policy, logger_sink=audit_defaults)
    run_guard(guard2)

    print("\n=== 3) Smart sampling (category-aware) ===")
    # Always log deny; plain permit sampled at 5%
    audit_smart = DecisionLogger(
        as_json=True,
        smart_sampling=True,
        sample_rate=0.05,
        category_sampling_rates={"deny": 1.0, "permit_with_obligations": 1.0, "permit": 0.05},
    )
    guard3 = Guard(policy=policy, logger_sink=audit_smart)
    # For deterministic output, you can set random.seed(...) before run_guard
    run_guard(guard3)

    print("\n=== 4) Env size limit (applied AFTER redactions) ===")
    audit_bound = DecisionLogger(
        as_json=True,
        use_default_redactions=True,
        max_env_bytes=300,  # intentionally small to show the truncation placeholder
    )
    guard4 = Guard(policy=policy, logger_sink=audit_bound)

    # Inflate context to exceed max_env_bytes after redactions
    big_ctx = Context(
        attrs={
            "ip": "10.0.0.5",
            "headers": {"authorization": "Bearer abc"},
            "cookies": {"sid": "C"},
            "extra": "Z" * 500,
        }
    )
    subj = Subject(
        id="u1",
        roles=["user"],
        attrs={"email": "user@example.com", "token": "t-123", "password": "p"},
    )
    res = Resource(type="doc", id="42", attrs={"archived": False, "secret": "s"})
    _ = guard4.evaluate_sync(
        subj, Action("read"), res, big_ctx
    )  # expect {"_truncated": true, ...} in env

    print("\nDone. Check JSON log lines above (logger name: 'rbacx.audit').")


if __name__ == "__main__":
    main()
