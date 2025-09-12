from __future__ import annotations

import hashlib
import json
import logging
import os
import random
import tempfile
import threading
import time
from typing import Any, Dict, Optional, Tuple

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
    """
    Policy source backed by a local JSON file.

    ETag semantics:
      - By default, ETag = SHA-256 of file content (a "strong" content validator).
      - If include_mtime_in_etag=True, the ETag also includes mtime (ns),
        so a simple "touch" (metadata-only change) will trigger a reload.

    To avoid unnecessary hashing, the class caches the last SHA by (size, mtime_ns).
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

        # Cache of last computed SHA keyed by file's (size, mtime_ns)
        self._cached_stat_sig: Optional[Tuple[int, int]] = None  # (size, mtime_ns)
        self._cached_sha: Optional[str] = None

    # --- helpers -------------------------------------------------------------

    def _stat_sig(self) -> Tuple[int, int]:
        st = os.stat(self.path)
        # Prefer nanosecond precision when available.
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
            # Reset cache so etag() returns None
            self._cached_stat_sig = None
            self._cached_sha = None
            return None, None

        if self._cached_stat_sig != sig or self._cached_sha is None:
            # Metadata changed -> recompute SHA
            sha = self._hash_file()
            self._cached_stat_sig = sig
            self._cached_sha = sha
        else:
            sha = self._cached_sha
        return sha, sig

    # --- PolicySource interface ---------------------------------------------

    def etag(self) -> Optional[str]:
        sha, sig = self._ensure_content_sha()
        if sha is None:
            return None
        if self.include_mtime_in_etag and sig is not None:
            # Join content SHA with mtime_ns; fixed width isn’t necessary here.
            return f"{sha}:{sig[1]}"
        return sha

    def load(self) -> Dict[str, Any]:
        # The file may change between etag() and load(); that's fine—next cycle will catch it.
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
    """
    Unified, production-grade policy reloader.

    Features:
      - ETag-first logic: call source.etag() and only load/apply when it changes.
      - Error suppression with exponential backoff + jitter to avoid log/IO storms.
      - Optional background polling loop with clean start/stop.
      - Backwards-compatible one-shot API aliases: refresh_if_needed()/poll_once().

    Notes:
      - If source.etag() returns None, we will attempt to load() and let the source decide.
      - Guard.set_policy(policy) is called only after a successful load().
      - This class is thread-safe for concurrent check_and_reload() calls.
    """

    def __init__(
        self,
        guard: Guard,
        source: PolicySource,
        *,
        poll_interval: float | None = 5.0,
        backoff_min: float = 2.0,
        backoff_max: float = 30.0,
        jitter_ratio: float = 0.15,
        thread_daemon: bool = True,
    ) -> None:
        self.guard = guard
        self.source = source
        self.poll_interval = poll_interval
        self.backoff_min = float(backoff_min)
        self.backoff_max = float(backoff_max)
        self.jitter_ratio = float(jitter_ratio)
        self.thread_daemon = bool(thread_daemon)

        # State
        try:
            self._last_etag: Optional[str] = self.source.etag()
        except Exception:
            self._last_etag = None
        self._suppress_until: float = 0.0
        self._backoff: float = self.backoff_min
        self._last_reload_at: float | None = None
        self._last_error: Exception | None = None

        # Concurrency
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    # --------------------------------------------------------------------- #
    # Public API
    # --------------------------------------------------------------------- #

    def check_and_reload(self) -> bool:
        """
        Perform a single reload check.

        Returns:
            True if a new policy was loaded and applied; otherwise False.
        """
        now = time.time()
        with self._lock:
            if now < self._suppress_until:
                return False

            try:
                etag = self.source.etag()
                # If etag is known and unchanged, skip loading.
                if etag is not None and etag == self._last_etag:
                    return False

                policy = self.source.load()
                self.guard.set_policy(policy)

                # Update state after successful apply.
                self._last_etag = etag
                self._last_reload_at = now
                self._last_error = None
                self._backoff = self.backoff_min  # reset backoff on success
                logger.info("RBACX: policy reloaded from %s", self._src_name())
                return True

            except json.JSONDecodeError as e:
                # Invalid JSON: suppress for a short backoff window.
                self._register_error(now, e, level="error", msg="RBACX: invalid policy JSON")
            except FileNotFoundError as e:
                # Source missing: common during bootstrapping or rotation.
                self._register_error(now, e, level="warning", msg="RBACX: policy not found: %s")
            except Exception as e:  # pragma: no cover
                # Any other unexpected errors.
                self._register_error(now, e, level="error", msg="RBACX: policy reload error")

            return False

    # Backwards-compatible aliases
    def refresh_if_needed(self) -> bool:
        return self.check_and_reload()

    def poll_once(self) -> bool:
        return self.check_and_reload()

    def start(self, interval: float | None = None) -> None:
        """
        Start the background polling thread.

        Args:
            interval: seconds between checks; if None, uses self.poll_interval (or 5.0 fallback).
        """
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            poll_iv = float(interval if interval is not None else (self.poll_interval or 5.0))
            self._stop_event.clear()
            self._thread = threading.Thread(
                target=self._run_loop, args=(poll_iv,), daemon=self.thread_daemon
            )
            self._thread.start()

    def stop(self, timeout: float | None = 1.0) -> None:
        """
        Signal the polling thread to stop and optionally wait for it.
        """
        with self._lock:
            if not self._thread:
                return
            self._stop_event.set()
            self._thread.join(timeout=timeout)
            # Don't keep a handle to a finished thread.
            if not self._thread.is_alive():
                self._thread = None

    # --------------------------------------------------------------------- #
    # Diagnostics (optional getters)
    # --------------------------------------------------------------------- #

    @property
    def last_etag(self) -> Optional[str]:
        with self._lock:
            return self._last_etag

    @property
    def last_reload_at(self) -> float | None:
        with self._lock:
            return self._last_reload_at

    @property
    def last_error(self) -> Exception | None:
        with self._lock:
            return self._last_error

    @property
    def suppressed_until(self) -> float:
        with self._lock:
            return self._suppress_until

    # --------------------------------------------------------------------- #
    # Internals
    # --------------------------------------------------------------------- #

    def _src_name(self) -> str:
        # Avoid importing the file source type here; use duck typing for a nicer message.
        path = getattr(self.source, "path", None)
        return path if isinstance(path, str) else self.source.__class__.__name__

    def _register_error(self, now: float, err: Exception, *, level: str, msg: str) -> None:
        """
        Log error/warning, advance backoff window with jitter, and set suppression.
        """
        self._last_error = err

        # Log with the requested level and source name if needed.
        log_msg = msg
        # IMPORTANT for mypy: keep a consistent tuple type for log_args.
        log_args: tuple[object, ...] = ()
        if "%s" in msg:
            log_args = (self._src_name(),)

        if level == "warning":
            logger.warning(log_msg, *log_args)
        else:
            logger.exception(log_msg, *log_args, exc_info=err)

        # Advance backoff (exponential) and apply jitter to suppression window.
        self._backoff = min(self.backoff_max, max(self.backoff_min, self._backoff * 2.0))
        jitter = self._backoff * self.jitter_ratio * random.uniform(-1.0, 1.0)
        self._suppress_until = now + max(0.2, self._backoff + jitter)

    def _run_loop(self, base_interval: float) -> None:
        """
        Background loop: periodically call check_and_reload() until stopped.
        """
        while not self._stop_event.is_set():
            try:
                self.check_and_reload()
            except Exception as e:  # pragma: no cover
                # Guard the loop itself; errors are already logged in check_and_reload(),
                # but in case of unexpected failures here, log and continue.
                logger.exception("RBACX: reloader loop error", exc_info=e)

            # Compute next sleep with jitter and suppression awareness.
            now = time.time()
            sleep_for = base_interval

            # Respect suppression window if it is shorter than the base interval.
            with self._lock:
                if now < self._suppress_until:
                    sleep_for = min(sleep_for, max(0.2, self._suppress_until - now))

            # Apply jitter to avoid synchronized polling across instances.
            jitter = base_interval * self.jitter_ratio * random.uniform(-1.0, 1.0)
            sleep_for = max(0.2, sleep_for + jitter)

            # Sleep in small chunks so stop() can interrupt promptly.
            end = time.time() + sleep_for
            while not self._stop_event.is_set():
                remaining = end - time.time()
                if remaining <= 0:
                    break
                self._stop_event.wait(timeout=min(0.5, remaining))


__all__ = ["atomic_write", "FilePolicySource", "HotReloader"]
