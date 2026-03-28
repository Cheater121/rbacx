import ipaddress
import logging
from typing import Any
from urllib.parse import urlparse

from rbacx.core.ports import PolicySource

from .policy_loader import parse_policy_text

logger = logging.getLogger("rbacx.store.http")

#: IP networks that are considered private / loopback / link-local.
#: Used by the optional SSRF guard (``block_private_ips=True``).
_PRIVATE_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local
    ipaddress.ip_network("0.0.0.0/8"),  # "this" network
    ipaddress.ip_network("::1/128"),  # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),  # IPv6 ULA (private)
    ipaddress.ip_network("fe80::/10"),  # IPv6 link-local
)


def _is_private_ip(host: str) -> bool:
    """Return True if *host* is a numeric IP address in a private/loopback range.

    Hostnames (non-numeric strings like ``"localhost"``) are **not** resolved —
    DNS resolution at validation time introduces a TOCTOU race and is out of
    scope.  Callers that require hostname blocking should resolve and validate
    *after* DNS resolution (e.g. via a custom ``requests`` session).
    """
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False  # not an IP literal — cannot determine without DNS
    return any(addr in net for net in _PRIVATE_NETWORKS)


class HTTPPolicySource(PolicySource):
    """HTTP policy source using ``requests`` with ETag support.

    Security parameters
    -------------------
    verify_ssl : bool
        Passed as ``verify`` to ``requests.get``.  Defaults to ``True``
        (certificate verification enabled).  Set to ``False`` only in
        development environments where you control the server.

    timeout : float
        Request timeout in seconds.  Defaults to ``5.0``.

    allow_redirects : bool
        Passed as ``allow_redirects`` to ``requests.get``.  Defaults to
        ``True``.  Set to ``False`` to prevent open-redirect abuse.

    allowed_schemes : tuple[str, ...]
        URL schemes that are permitted.  Defaults to ``("http", "https")``.
        To restrict to HTTPS only, pass ``("https",)``.

    block_private_ips : bool
        When ``True``, raises ``ValueError`` if the URL's host is a numeric
        IP address in a private, loopback, or link-local range (SSRF guard).
        Hostname literals (e.g. ``"localhost"``) are **not** blocked by this
        flag because they require DNS resolution; use network-level controls
        for hostname-based SSRF protection.  Defaults to ``False`` to preserve
        backward compatibility.

    Extra: rbacx[http]
    """

    def __init__(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        validate_schema: bool = False,
        verify_ssl: bool = True,
        timeout: float = 5.0,
        allow_redirects: bool = True,
        allowed_schemes: tuple[str, ...] = ("http", "https"),
        block_private_ips: bool = False,
    ) -> None:
        self._validate_url(url, allowed_schemes, block_private_ips)
        self.url = url
        self.validate_schema = validate_schema
        self.headers = dict(headers or {})
        self.verify_ssl = bool(verify_ssl)
        self.timeout = float(timeout)
        self.allow_redirects = bool(allow_redirects)
        self._etag: str | None = None
        self._policy_cache: dict[str, Any] | None = None

    # ------------------------------------------------------------------
    # URL validation helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_url(
        url: str,
        allowed_schemes: tuple[str, ...],
        block_private_ips: bool,
    ) -> None:
        """Validate *url* against scheme whitelist and optional SSRF guard.

        Raises ``ValueError`` with a descriptive message if the URL is
        rejected.  Called once at construction time so that invalid
        configurations are caught eagerly rather than at load time.
        """
        parsed = urlparse(url)
        scheme = (parsed.scheme or "").lower()
        if scheme not in {s.lower() for s in allowed_schemes}:
            raise ValueError(
                f"HTTPPolicySource: URL scheme {scheme!r} is not allowed "
                f"(allowed: {allowed_schemes!r}).  "
                f"Pass allowed_schemes=('http', 'https') to permit HTTP."
            )
        if block_private_ips:
            host = parsed.hostname or ""
            if _is_private_ip(host):
                raise ValueError(
                    f"HTTPPolicySource: URL host {host!r} resolves to a "
                    f"private/loopback IP address (SSRF guard).  "
                    f"Pass block_private_ips=False to disable this check."
                )

    # ------------------------------------------------------------------
    # PolicySource interface
    # ------------------------------------------------------------------

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

        r = requests.get(
            self.url,
            headers=hdrs,
            timeout=self.timeout,
            verify=self.verify_ssl,
            allow_redirects=self.allow_redirects,
        )

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
                logger.debug(
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
