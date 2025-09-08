
from __future__ import annotations

from typing import Any, Dict, List


def _ensure_list_size(lst: list, idx: int) -> None:
    while len(lst) <= idx:
        lst.append({})

def _set_by_path(obj: Any, path: str, value: Any) -> None:
    """Supports dot paths with list indices, e.g. items[1].email"""
    parts = path.split(".")
    cur = obj
    for i, p in enumerate(parts):
        is_last = i == len(parts) - 1
        if "[" in p and p.endswith("]"):
            key, idx_str = p.split("[", 1)
            idx = int(idx_str[:-1])
            if key not in cur or not isinstance(cur[key], list):
                cur[key] = []
            _ensure_list_size(cur[key], idx)
            if is_last:
                cur[key][idx] = value
                return
            if not isinstance(cur[key][idx], dict):
                cur[key][idx] = {}
            cur = cur[key][idx]
        else:
            if is_last:
                if isinstance(cur, dict):
                    cur[p] = value
                return
            if p not in cur or not isinstance(cur[p], dict):
                cur[p] = {}
            cur = cur[p]

def apply_obligations(payload: Dict[str, Any], obligations: List[Dict[str, Any]]) -> Dict[str, Any]:
    out = dict(payload)
    for ob in obligations or []:
        t = ob.get("type")
        if t == "mask_fields":
            placeholder = ob.get("placeholder", "***")
            for path in ob.get("fields", []):
                _set_by_path(out, path, placeholder)
        if t == "redact_fields":
            for path in ob.get("fields", []):
                _set_by_path(out, path, "[REDACTED]")
    return out
