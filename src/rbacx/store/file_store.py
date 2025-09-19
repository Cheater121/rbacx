from __future__ import annotations

import hashlib
import logging
import os
import tempfile
from typing import Any, Dict, Optional, Tuple

from ..core.ports import PolicySource
from .policy_loader import parse_policy_text

logger = logging.getLogger("rbacx.store.file")


def atomic_write(path: str, data: str, *, encoding: str = "utf-8") -> None:
    """Write data atomically to *path* using a temp file + os.replace()."""
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
    """
    Policy source backed by a local JSON file.

    ETag semantics:
      - By default, ETag = SHA-256 of file content.
      - If include_mtime_in_etag=True, the ETag also includes mtime (ns),
        so a simple "touch" (metadata-only change) will trigger a reload.

    The class caches the last SHA by (size, mtime_ns) to avoid unnecessary hashing.
    """

    def __init__(
        self,
        path: str,
        *,
        validate_schema: bool = False,
        include_mtime_in_etag: bool = False,
        chunk_size: int = 512 * 1024,
    ) -> None:
        self.path = path
        self.validate_schema = validate_schema
        self.include_mtime_in_etag = include_mtime_in_etag
        self._chunk_size = int(chunk_size)

        self._cached_stat_sig: Optional[Tuple[int, int]] = None  # (size, mtime_ns)
        self._cached_sha: Optional[str] = None

    # helpers ----------------------------------------------------------------

    def _stat_sig(self) -> Tuple[int, int]:
        st = os.stat(self.path)
        mtime_ns = getattr(st, "st_mtime_ns", int(st.st_mtime * 1_000_000_000))
        return (st.st_size, mtime_ns)

    def _hash_file(self) -> str:
        h = hashlib.sha256()
        with open(self.path, "rb") as f:
            for chunk in iter(lambda: f.read(self._chunk_size), b""):
                h.update(chunk)
        return h.hexdigest()

    def _ensure_content_sha(self) -> Tuple[Optional[str], Optional[Tuple[int, int]]]:
        try:
            sig = self._stat_sig()
        except FileNotFoundError:
            self._cached_stat_sig = None
            self._cached_sha = None
            return None, None

        if self._cached_stat_sig != sig or self._cached_sha is None:
            sha = self._hash_file()
            self._cached_stat_sig = sig
            self._cached_sha = sha
        else:
            sha = self._cached_sha
        return sha, sig

    # PolicySource ------------------------------------------------------------

    def etag(self) -> Optional[str]:
        sha, sig = self._ensure_content_sha()
        if sha is None:
            return None
        if self.include_mtime_in_etag and sig is not None:
            return f"{sha}:{sig[1]}"
        return sha

    def load(self) -> Dict[str, Any]:
        with open(self.path, "r", encoding="utf-8") as f:
            text = f.read()
        policy = parse_policy_text(text, filename=self.path)

        if self.validate_schema:
            try:
                from rbacx.dsl.validate import validate_policy

                validate_policy(policy)
            except Exception as e:  # pragma: no cover
                logger.exception("RBACX: policy validation failed", exc_info=e)
                raise

        return policy


__all__ = ["FilePolicySource", "atomic_write"]
