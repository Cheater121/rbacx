from __future__ import annotations

import threading
from typing import Optional

from ..core.engine import Guard
from ..core.ports import PolicySource


class PolicyManager:
    """Manages policy retrieval from a PolicySource and updates a Guard.

    - poll_once(): fetch and update if etag changed
    - start_polling(interval_s): background polling thread (daemon)
    """

    def __init__(self, guard: Guard, source: PolicySource) -> None:
        # NOTE: test suite constructs as PolicyManager(guard, source)
        self.guard = guard
        self.source = source
        self._last_etag: Optional[str] = getattr(guard, "policy_etag", None)
        self._thr: Optional[threading.Thread] = None
        self._stop = threading.Event()

    def poll_once(self) -> bool:
        """Fetch policy from source and apply it if etag changed.

        Returns True if a new policy was applied, False otherwise.
        """
        policy = self.source.load()
        etag = self.source.etag()
        if not policy:
            return False
        if etag and etag == self._last_etag:
            return False
        self.guard.set_policy(policy)
        self._last_etag = etag
        return True

    def start_polling(self, interval_s: int = 5) -> None:
        """Start background polling thread if not already running."""
        if self._thr is not None and self._thr.is_alive():
            return
        self._stop.clear()

        def _loop() -> None:
            while not self._stop.is_set():
                try:
                    self.poll_once()
                except Exception:
                    # swallow errors; next iteration will retry
                    pass
                self._stop.wait(interval_s)

        self._thr = threading.Thread(
            target=_loop, name="rbacx-policy-poller", daemon=True
        )
        self._thr.start()

    def stop(self) -> None:
        """Stop background polling thread (if running)."""
        self._stop.set()
        if self._thr:
            self._thr.join(timeout=1)
