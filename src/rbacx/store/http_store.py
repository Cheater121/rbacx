from __future__ import annotations

from typing import Any, Dict, Optional

from rbacx.core.ports import PolicySource

from .policy_loader import parse_policy_text


class HTTPPolicySource(PolicySource):
    """HTTP policy source using `requests` with ETag support.
    Extra: rbacx[http]
    """

    def __init__(self, url: str, *, headers: Dict[str, str] | None = None) -> None:
        self.url = url
        self.headers = headers or {}
        self._etag: Optional[str] = None

    def load(self) -> Dict[str, Any]:
        try:
            import requests  # type: ignore
        except Exception as e:  # pragma: no cover
            raise RuntimeError(
                "requests is required for HTTPPolicySource (pip install rbacx[http])"
            ) from e

        hdrs = dict(self.headers)
        if self._etag:
            hdrs["If-None-Match"] = self._etag

        r = requests.get(self.url, headers=hdrs, timeout=10)

        # Normalize headers dict for case-insensitive access (stubs may use plain dict)
        raw_headers = getattr(r, "headers", {}) or {}
        headers_ci: Dict[str, str] = {}
        try:
            # requests provides a CaseInsensitiveDict, which is already case-insensitive,
            # but to support plain dict stubs we normalize keys to lowercase.
            for k, v in raw_headers.items():
                headers_ci[k.lower()] = v
        except Exception:
            # In case headers is not iterable/mapping-like
            headers_ci = {}

        if r.status_code == 304 and self._etag:
            # Not modified, return empty dict so caller can skip processing
            return {}

        r.raise_for_status()

        # Update ETag case-insensitively
        self._etag = headers_ci.get("etag", self._etag)

        # Content-Type for format hinting
        content_type = headers_ci.get("content-type", "")
        ct_lower = (content_type or "").lower()
        is_yaml = ("yaml" in ct_lower) or self.url.lower().endswith((".yaml", ".yml"))

        # Prefer JSON when it's not YAML and .json() exists (backward compatible with test stubs)
        if not is_yaml and hasattr(r, "json"):
            try:
                return r.json()  # type: ignore[no-any-return]
            except Exception:
                # Fall back to text-based parsing below
                pass

        # Text/content fallback (covers YAML and text bodies)
        body_text = getattr(r, "text", None)
        if body_text is None:
            # Some stubs don't provide .text; use .content if available
            content = getattr(r, "content", None)
            if isinstance(content, (bytes, bytearray)):
                try:
                    body_text = content.decode("utf-8")
                except Exception:
                    body_text = ""
            else:
                body_text = ""

        return parse_policy_text(body_text, filename=self.url, content_type=content_type)

    def etag(self) -> Optional[str]:
        return self._etag
