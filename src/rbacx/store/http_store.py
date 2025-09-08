
from __future__ import annotations

from typing import Any, Dict, Optional


class HTTPPolicySource:
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
            raise RuntimeError("requests is required for HTTPPolicySource (pip install rbacx[http])") from e
        hdrs = dict(self.headers)
        if self._etag:
            hdrs["If-None-Match"] = self._etag
        r = requests.get(self.url, headers=hdrs, timeout=10)
        if r.status_code == 304 and self._etag:
            # not modified, return empty dict so caller can skip
            return {}
        r.raise_for_status()
        self._etag = r.headers.get("ETag", self._etag)
        return r.json()

    def etag(self) -> Optional[str]:
        return self._etag
