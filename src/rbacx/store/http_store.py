from typing import Any

from rbacx.core.ports import PolicySource

from .policy_loader import parse_policy_text


class HTTPPolicySource(PolicySource):
    """HTTP policy source using `requests` with ETag support.
    Extra: rbacx[http]
    """

    def __init__(
        self, url: str, *, headers: dict[str, str] | None = None, validate_schema: bool = False
    ) -> None:
        self.url = url
        # Optional schema validation flag (disabled by default)
        self.validate_schema = validate_schema
        self.headers = dict(headers or {})
        self._etag: str | None = None
        self._policy_cache: dict[str, Any] | None = None

    def load(self) -> dict[str, Any]:
        try:
            import requests  # type: ignore[import-untyped]
        except Exception as e:  # pragma: no cover - optional extra
            raise RuntimeError("requests is required (install rbacx[http])") from e

        # Build request headers, preserving user-specified values
        hdrs: dict[str, str] = dict(self.headers)
        if self._etag:
            # Conditional GET to avoid downloading body if unchanged
            hdrs.setdefault("If-None-Match", self._etag)

        r = requests.get(self.url, headers=hdrs, timeout=5)

        # 304 Not Modified: return previously cached policy without mutation
        if getattr(r, "status_code", None) == 304:
            # No change; keep existing ETag (server didn't send a new one)
            if self._policy_cache is not None:
                return self._policy_cache
            # Defensive: on first load with 304 (shouldn't happen), return empty dict
            return {}

        # Any other non-2xx should raise
        if hasattr(r, "raise_for_status"):
            r.raise_for_status()

        # Update cached ETag if server provided it (case-insensitive)
        etag_header: str | None = None
        try:
            # requests' Headers are case-insensitive, but stubs may be plain dicts
            etag_header = r.headers.get("ETag") if hasattr(r, "headers") else None
            if etag_header is None and isinstance(getattr(r, "headers", None), dict):
                # try lowercase key for simple stubs
                etag_header = r.headers.get("etag")
        except Exception:
            etag_header = None
        if isinstance(etag_header, str) and etag_header:
            self._etag = etag_header

        # JSON fast-path: if a .json() method exists, try it regardless of headers.
        # Many tests/stubs provide only .json() with no .text/.content or Content-Type.
        if hasattr(r, "json"):
            try:
                obj = r.json()
                if isinstance(obj, dict):
                    # Optionally validate the policy before returning
                    if self.validate_schema:
                        from rbacx.dsl.validate import validate_policy

                        validate_policy(obj)
                    self._policy_cache = obj
                    return obj
            except Exception:
                # fall through to text parsing below
                __import__("logging").getLogger("rbacx.store.http").debug(
                    "HTTPPolicySource: failed to parse JSON from response; falling back to text parsing",
                    exc_info=True,
                )

        # Determine content-type for parser hints
        content_type: str | None = None
        try:
            ctype = r.headers.get("Content-Type") if hasattr(r, "headers") else None
            if ctype is None and isinstance(getattr(r, "headers", None), dict):
                ctype = r.headers.get("content-type")
            if isinstance(ctype, str):
                content_type = ctype
        except Exception:
            content_type = None

        # Obtain text body; some stubs provide only .text, others only .content
        body_text: str | None = getattr(r, "text", None)
        if body_text is None:
            content = getattr(r, "content", None)
            if isinstance(content, (bytes, bytearray)):
                try:
                    body_text = content.decode("utf-8")
                except Exception:
                    body_text = ""
            else:
                body_text = ""

        # If Content-Type indicates JSON but body text is empty, try JSON API as a last resort
        if (
            (body_text or "") == ""
            and content_type
            and "json" in content_type.lower()
            and hasattr(r, "json")
        ):
            obj = None
            try:
                obj = r.json()
            except Exception:
                # If .json() fails, fall through to text parsing
                obj = None
            if isinstance(obj, dict):
                # Optionally validate; let validation errors propagate
                if self.validate_schema:
                    from rbacx.dsl.validate import validate_policy

                    validate_policy(obj)
                self._policy_cache = obj
                return obj

        policy = parse_policy_text(body_text or "", filename=self.url, content_type=content_type)
        # Run schema validation only when explicitly enabled (text branch)
        if self.validate_schema:
            from rbacx.dsl.validate import validate_policy

            validate_policy(policy)
        # Cache the last successfully parsed policy for 304 reuse
        self._policy_cache = policy
        return policy

    def etag(self) -> str | None:
        return self._etag
