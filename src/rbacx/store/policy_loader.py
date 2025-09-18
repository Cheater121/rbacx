from __future__ import annotations

import json
from typing import Any, Dict, Literal, Optional

_YAML_MIME_MARKERS = ("yaml", "x-yaml")
_JSON_MIME_MARKERS = ("json",)

PolicyFormat = Literal["json", "yaml"]


def _detect_format(
    *, filename: Optional[str] = None, content_type: Optional[str] = None, fmt: Optional[str] = None
) -> PolicyFormat:
    """Detect desired policy format.

    Priority:
      1) explicit *fmt* argument ("json"|"yaml")
      2) HTTP/S3 Content-Type header
      3) Filename extension
      4) Default to JSON

    This function never raises for unknown/ambiguous inputs — it falls back to JSON.
    """
    if fmt and fmt.lower() in ("json", "yaml"):
        return fmt.lower()  # type: ignore[return-value]

    # Content-Type check
    if content_type:
        ct = content_type.lower()
        if any(marker in ct for marker in _YAML_MIME_MARKERS):
            return "yaml"
        if any(marker in ct for marker in _JSON_MIME_MARKERS):
            return "json"

    # Extension check
    if filename:
        fn = filename.lower()
        if fn.endswith((".yaml", ".yml")):
            return "yaml"
        if fn.endswith(".json"):
            return "json"

    return "json"


def _parse_yaml(text: str) -> Dict[str, Any]:
    try:
        import yaml  # type: ignore
    except Exception as e:  # pragma: no cover
        raise ImportError(
            "YAML support requires the optional dependency PyYAML. Install with: pip install 'rbacx[yaml]'"
        ) from e
    # Use safe_load to avoid executing arbitrary tags/constructors.
    data = yaml.safe_load(text)
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValueError("Policy YAML must be a mapping at the top level")
    return data


def parse_policy_text(
    text: str,
    *,
    filename: Optional[str] = None,
    content_type: Optional[str] = None,
    fmt: Optional[str] = None,
) -> Dict[str, Any]:
    """Parse a policy document from a *text* string.

    Chooses JSON or YAML based on *fmt* / *content_type* / *filename*.
    Returns a Python dict suitable for the engine's JSON Schema validation.
    """
    pf = _detect_format(filename=filename, content_type=content_type, fmt=fmt)
    if pf == "json":
        return json.loads(text)
    else:
        return _parse_yaml(text)


def parse_policy_bytes(
    data: bytes,
    *,
    filename: Optional[str] = None,
    content_type: Optional[str] = None,
    fmt: Optional[str] = None,
    encoding: str = "utf-8",
) -> Dict[str, Any]:
    """Parse a policy document from raw *bytes* (e.g., S3 object body).

    Decodes using *encoding* (default UTF-8) then delegates to :func:`parse_policy_text`.
    """
    return parse_policy_text(
        data.decode(encoding), filename=filename, content_type=content_type, fmt=fmt
    )
