# src/rbacx/obligations/enforcer.py
from __future__ import annotations

import copy
from typing import Any, Dict, List


def _ensure_list_size(lst: list, idx: int) -> None:
    """Grow a list with empty dicts until it has at least `idx + 1` items."""
    while len(lst) <= idx:
        lst.append({})


def _set_by_path(obj: Any, path: str, value: Any) -> None:
    """
    Set a nested value by a dotted path with optional list indices.
    Examples:
      - "user.email"
      - "items[0].price"
    Notes:
      - If the traversal meets a non-dict where a dict is required, the
        operation is a no-op (defensive fail-safe).
    """
    parts = str(path).split(".")
    cur = obj
    for i, p in enumerate(parts):
        is_last = i == len(parts) - 1

        # List segment like "items[3]"
        if "[" in p and p.endswith("]"):
            key, idx_str = p.split("[", 1)
            try:
                idx = int(idx_str[:-1])  # strip closing "]"
            except Exception:
                return  # invalid index → no-op

            if not isinstance(cur, dict):
                return  # cannot descend into a non-dict container

            if key not in cur or not isinstance(cur[key], list):
                cur[key] = []
            _ensure_list_size(cur[key], idx)

            if is_last:
                cur[key][idx] = value
                return

            if not isinstance(cur[key][idx], dict):
                cur[key][idx] = {}
            cur = cur[key][idx]
            continue

        # Dict segment like "user" or final scalar like "email"
        if not isinstance(cur, dict):
            return  # cannot create keys on a non-dict container

        if is_last:
            cur[p] = value
            return

        if p not in cur or not isinstance(cur[p], dict):
            cur[p] = {}
        cur = cur[p]


def apply_obligations(
    payload: Dict[str, Any],
    obligations: List[Dict[str, Any]] | None,
    *,
    in_place: bool = False,
) -> Dict[str, Any]:
    """
    Apply masking/redaction obligations to a payload.

    Semantics:
      - By default (in_place=False): return a DEEP-COPIED payload with changes applied.
        The original `payload` is NOT mutated (uses `copy.deepcopy`).
      - If in_place=True: mutate `payload` directly and return the same reference.

    Supported obligation shapes:
      - {"type": "mask_fields", "placeholder": "***", "fields": ["user.email", "items[0].price"]}
      - {"type": "redact_fields", "fields": ["user.name"]}

    Unknown obligation types are ignored.
    """
    # Use deep copy by default so nested structures are independent from the source.
    out = payload if in_place else copy.deepcopy(payload)

    for ob in obligations or []:
        t = ob.get("type")
        if t == "mask_fields":
            placeholder = ob.get("placeholder", "***")
            for path in ob.get("fields", []) or []:
                _set_by_path(out, path, placeholder)
        elif t == "redact_fields":
            for path in ob.get("fields", []) or []:
                _set_by_path(out, path, "[REDACTED]")
        else:
            # Unknown obligation type: intentionally ignore.
            continue

    return out
