# src/rbacx/store/manager.py
from __future__ import annotations

import warnings

from ..core.engine import Guard
from ..core.ports import PolicySource
from ..policy.loader import HotReloader


class PolicyManager:
    """
    Back-compat shim around HotReloader with legacy semantics:

    - Constructor keeps legacy arg order: (guard, source).
    - First poll applies the policy even if the initial ETag snapshot equals the current one.
    - start_polling() performs an initial apply before starting the background thread.
    - No duplicated reload logic; it delegates to HotReloader.
    """

    def __init__(
        self,
        guard: Guard,
        source: PolicySource,
        *,
        poll_interval: float = 5.0,
        initial_load: bool = True,
    ) -> None:
        warnings.warn(
            "rbacx.store.manager.PolicyManager is deprecated; "
            "use rbacx.policy.loader.HotReloader",
            DeprecationWarning,
            stacklevel=2,
        )
        # IMPORTANT: legacy arg order (guard, source)
        self._r = HotReloader(guard=guard, source=source, poll_interval=poll_interval)
        # legacy behavior: perform an initial apply on the first poll
        self._needs_initial_apply = bool(initial_load)

    def poll_once(self) -> bool:
        if self._needs_initial_apply:
            # Force the next check to load by invalidating the remembered ETag snapshot.
            # Using None guarantees a reload regardless of current source.etag() value.
            try:
                self._r._last_etag = None  # type: ignore[attr-defined]
            except Exception:
                pass
            self._needs_initial_apply = False
        return self._r.check_and_reload()

    def start_polling(self, interval_s: float = 5.0) -> None:
        # Legacy: do an initial apply before starting the background thread
        self._needs_initial_apply = True
        self.poll_once()
        self._r.start(interval=interval_s)

    def stop(self) -> None:
        self._r.stop()


__all__ = ["PolicyManager"]
