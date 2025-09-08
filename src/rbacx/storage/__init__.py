from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
import time
from typing import Any, Dict, Optional

from ..core.engine import Guard
from ..core.ports import PolicySource

logger = logging.getLogger("rbacx.storage")


def atomic_write(path: str, data: str, *, encoding: str = "utf-8") -> None:
    """Write data atomically to *path*.

    Uses a temporary file in the same directory followed by os.replace().
    """
    directory = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(prefix=".rbacx.tmp.", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding=encoding) as f:
            f.write(data)
        os.replace(tmp, path)
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass


class FilePolicySource(PolicySource):
    """Load policy JSON from a file path and compute its etag (sha256 of content)."""

    def __init__(self, path: str, *, validate_schema: bool = False) -> None:
        self.path = path
        self.validate_schema = validate_schema
        self._last_sha: Optional[str] = None

    def _compute_sha(self) -> Optional[str]:
        try:
            with open(self.path, "rb") as f:
                data = f.read()
            return hashlib.sha256(data).hexdigest()
        except FileNotFoundError:
            return None

    def etag(self) -> Optional[str]:
        return self._compute_sha()

    def load(self) -> Dict[str, Any]:
        with open(self.path, "r", encoding="utf-8") as f:
            text = f.read()
        policy = json.loads(text)
        if self.validate_schema:
            try:
                from rbacx.dsl.validate import validate_policy  # type: ignore[import-not-found]
                validate_policy(policy)
            except Exception as e:  # pragma: no cover
                logger.exception("RBACX: policy validation failed", exc_info=e)
                raise
        return policy


class HotReloader:
    """Periodically reload policy from a PolicySource into a Guard.

    - Tracks source ETag and only reloads on change.
    - Suppresses frequent retries for a short time after errors.
    """

    def __init__(self, guard: Guard, source: PolicySource, *, poll_interval: float | None = 5.0) -> None:
        self.guard = guard
        self.source = source
        self.poll_interval = poll_interval
        # Initialize with current etag so the *first* check doesn't report change.
        try:
            self._last_etag: Optional[str] = self.source.etag()
        except Exception:
            self._last_etag = None
        self._suppress_until: float = 0.0

    def _src_name(self) -> str:
        if isinstance(self.source, FilePolicySource):
            return getattr(self.source, "path", "<file>")
        return self.source.__class__.__name__

    def check_and_reload(self) -> bool:
        """Check the source; if ETag changed, load and apply to guard.

        Returns True iff policy was reloaded and applied.
        """
        now = time.time()
        if now < self._suppress_until:
            return False
        try:
            etag = self.source.etag()
            if etag is not None and etag == self._last_etag:
                return False
            policy = self.source.load()
            # apply
            self.guard.set_policy(policy)
            # update last etag after successful load/apply
            self._last_etag = etag
            logger.info("RBACX: policy reloaded from %s", self._src_name())
            return True
        except json.JSONDecodeError as e:
            logger.exception("RBACX: invalid policy JSON", exc_info=e)
            self._suppress_until = now + max(2.0, self.poll_interval or 0.5)
        except FileNotFoundError:
            logger.warning("RBACX: policy not found: %s", self._src_name())
            self._suppress_until = now + max(2.0, self.poll_interval or 0.5)
        except Exception as e:
            logger.exception("RBACX: policy reload error", exc_info=e)
            self._suppress_until = now + max(2.0, self.poll_interval or 0.5)
        return False


__all__ = ["atomic_write", "FilePolicySource", "HotReloader"]
