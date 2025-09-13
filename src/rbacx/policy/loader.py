from __future__ import annotations

import json
import logging
import random
import threading
import time
import warnings
from typing import Optional

from ..core.engine import Guard
from ..core.ports import PolicySource
from ..store.file_store import FilePolicySource  # re-exported here for convenience

logger = logging.getLogger("rbacx.policy.loader")


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

    Parameters:
      initial_load:
          Controls startup behavior.
          - False (default): prime ETag at construction time; the first check will NO-OP
            unless the policy changes. (Backwards-compatible with previous versions.)
          - True: do not prime ETag; the first check will load the current policy.
    """

    def __init__(
        self,
        guard: Guard,
        source: PolicySource,
        *,
        initial_load: bool = False,
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

        self._initial_load = bool(initial_load)

        # Initial state: either "prime" ETag (legacy) or make the first check load.
        try:
            if self._initial_load:
                self._last_etag: Optional[str] = None
            else:
                self._last_etag = self.source.etag()
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

    # Public API -------------------------------------------------------------

    def check_and_reload(self, *, force: bool = False) -> bool:
        """
        Perform a single reload check.

        Args:
            force: If True, load/apply the policy regardless of ETag state.

        Returns:
            True if a new policy was loaded and applied; otherwise False.
        """
        now = time.time()
        with self._lock:
            if now < self._suppress_until:
                return False

            try:
                if force:
                    # Force a load regardless of etag
                    policy = self.source.load()
                    self.guard.set_policy(policy)

                    try:
                        self._last_etag = self.source.etag()
                    except Exception:
                        self._last_etag = None

                    self._last_reload_at = now
                    self._last_error = None
                    self._backoff = self.backoff_min
                    logger.info("RBACX: policy force-loaded from %s", self._src_name())
                    return True

                etag = self.source.etag()
                if etag is not None and etag == self._last_etag:
                    return False

                policy = self.source.load()
                self.guard.set_policy(policy)

                self._last_etag = etag
                self._last_reload_at = now
                self._last_error = None
                self._backoff = self.backoff_min
                logger.info("RBACX: policy reloaded from %s", self._src_name())
                return True

            except json.JSONDecodeError as e:
                self._register_error(now, e, level="error", msg="RBACX: invalid policy JSON")
            except FileNotFoundError as e:
                self._register_error(now, e, level="warning", msg="RBACX: policy not found: %s")
            except Exception as e:  # pragma: no cover
                logger.exception("RBACX: policy reload error", exc_info=e)
                self._register_error(now, e, level="error", msg="RBACX: policy reload error")

            return False

    # Backwards-compatible aliases
    def refresh_if_needed(self) -> bool:
        return self.check_and_reload()

    def poll_once(self) -> bool:
        return self.check_and_reload()

    def start(
        self,
        interval: float | None = None,
        *,
        initial_load: Optional[bool] = None,
        force_initial: bool = False,
    ) -> None:
        """
        Start the background polling thread.

        Args:
            interval: seconds between checks; if None, uses self.poll_interval (or 5.0 fallback).
            initial_load: override constructor's initial_load just for this start().
                          If True, perform a synchronous load/check before starting the thread.
                          If False, skip any initial load.
                          If None, inherit the constructor setting.
            force_initial: if True and an initial load is requested, bypass the ETag check
                           for that initial load (equivalent to check_and_reload(force=True)).
        """
        with self._lock:
            if self._thread and self._thread.is_alive():
                return

            poll_iv = float(interval if interval is not None else (self.poll_interval or 5.0))
            self._stop_event.clear()

            # Optional synchronous initial check before the loop starts
            want_initial = self._initial_load if initial_load is None else bool(initial_load)
            if want_initial:
                # RLock allows re-entrancy here
                self.check_and_reload(force=force_initial)

            self._thread = threading.Thread(
                target=self._run_loop, args=(poll_iv,), daemon=self.thread_daemon
            )
            self._thread.start()

    def stop(self, timeout: float | None = 1.0) -> None:
        """Signal the polling thread to stop and optionally wait for it."""
        with self._lock:
            if not self._thread:
                return
            self._stop_event.set()
            self._thread.join(timeout=timeout)
            if not self._thread.is_alive():
                self._thread = None

    # Diagnostics ------------------------------------------------------------

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

    # Internals --------------------------------------------------------------

    def _src_name(self) -> str:
        path = getattr(self.source, "path", None)
        return path if isinstance(path, str) else self.source.__class__.__name__

    def _register_error(self, now: float, err: Exception, *, level: str, msg: str) -> None:
        """Log error/warning, advance backoff window with jitter, and set suppression."""
        self._last_error = err

        log_msg = msg
        log_args: tuple[object, ...] = ()
        if "%s" in msg:
            log_args = (self._src_name(),)

        if level == "warning":
            logger.warning(log_msg, *log_args)
        else:
            logger.exception(log_msg, *log_args, exc_info=err)

        self._backoff = min(self.backoff_max, max(self.backoff_min, self._backoff * 2.0))
        jitter = self._backoff * self.jitter_ratio * random.uniform(-1.0, 1.0)
        self._suppress_until = now + max(0.2, self._backoff + jitter)

    def _run_loop(self, base_interval: float) -> None:
        """Background loop: periodically call check_and_reload() until stopped."""
        while not self._stop_event.is_set():
            try:
                self.check_and_reload()
            except Exception as e:  # pragma: no cover
                logger.exception("RBACX: reloader loop error", exc_info=e)

            now = time.time()
            sleep_for = base_interval
            with self._lock:
                if now < self._suppress_until:
                    sleep_for = min(sleep_for, max(0.2, self._suppress_until - now))

            jitter = base_interval * self.jitter_ratio * random.uniform(-1.0, 1.0)
            sleep_for = max(0.2, sleep_for + jitter)

            end = time.time() + sleep_for
            while not self._stop_event.is_set():
                remaining = end - time.time()
                if remaining <= 0:
                    break
                self._stop_event.wait(timeout=min(0.5, remaining))


class ReloadingPolicyManager:
    """
    DEPRECATED: Use HotReloader instead.

    Compatibility wrapper that delegates to HotReloader.

    This keeps older imports/tests working:
      from rbacx.policy.loader import ReloadingPolicyManager
    """

    def __init__(self, source: PolicySource, guard: Guard) -> None:
        warnings.warn(
            "ReloadingPolicyManager is deprecated and will be removed in a future release; "
            "use HotReloader instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        logger.warning(
            "RBACX: ReloadingPolicyManager is deprecated and will be removed in a future release; "
            "use HotReloader instead."
        )
        self._r = HotReloader(guard=guard, source=source)

    def refresh_if_needed(self) -> bool:
        return self._r.check_and_reload()


def load_policy(path: str) -> dict:
    """Convenience loader to satisfy tests that import a loader function."""
    return FilePolicySource(path).load()


__all__ = ["HotReloader", "ReloadingPolicyManager", "FilePolicySource", "load_policy"]
