"""
Lightweight caching abstractions for RBACX.

This module provides a protocol-based cache interface and a default in-memory
LRU+TTL implementation suitable for single-process use. The default cache is
intentionally simple and dependency-free to align with KISS and Clean Architecture:
production deployments can provide their own cache implementation that satisfies
the protocol (e.g., Redis-backed) and inject it into the Guard.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Optional, Protocol


class AbstractCache(Protocol):
    """Minimal cache interface for dependency inversion.

    Implementations MUST be safe to call from multiple threads in-process or be
    clearly documented otherwise.

    get should return None if a key doesn't exist or is expired.
    set may accept an optional TTL in seconds.
    """

    def get(self, key: str) -> Optional[Any]:  # pragma: no cover - protocol
        ...

    def set(
        self, key: str, value: Any, ttl: Optional[int] = None
    ) -> None:  # pragma: no cover - protocol
        ...

    def delete(self, key: str) -> None:  # pragma: no cover - protocol
        ...

    def clear(self) -> None:  # pragma: no cover - protocol
        ...


@dataclass
class _Entry:
    value: Any
    expires_at: Optional[float]  # monotonic timestamp


class DefaultInMemoryCache(AbstractCache):
    """Thread-safe in-memory LRU cache with optional per-key TTL.

    Notes
    -----
    - Uses time.monotonic() for TTL to avoid wall clock changes.
    - Designed for *single process* scenarios. For multi-process/multi-host,
      inject a distributed cache implementation that conforms to AbstractCache.
    - Values are stored as-is; callers are responsible for storing immutable
      or copy-safe data if necessary.
    """

    def __init__(self, maxsize: int = 2048) -> None:
        self._data: "OrderedDict[str, _Entry]" = OrderedDict()
        self._maxsize = int(maxsize)
        self._lock = threading.RLock()

    def _purge_expired_unlocked(self) -> None:
        now = time.monotonic()
        to_delete = []
        # Avoid O(n) scan on every get by lazily purging only a small prefix.
        for k, entry in list(self._data.items())[:128]:
            if entry.expires_at is not None and entry.expires_at <= now:
                to_delete.append(k)
        for k in to_delete:
            self._data.pop(k, None)

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            entry = self._data.get(key)
            if entry is None:
                return None
            if entry.expires_at is not None and entry.expires_at <= time.monotonic():
                # Expired; remove lazily.
                self._data.pop(key, None)
                return None
            # LRU: move to end
            self._data.move_to_end(key)
            return entry.value

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        expires_at = None
        if ttl is not None and ttl > 0:
            expires_at = time.monotonic() + float(ttl)
        with self._lock:
            self._data[key] = _Entry(value=value, expires_at=expires_at)
            self._data.move_to_end(key)
            # Evict while above capacity
            while len(self._data) > self._maxsize:
                self._data.popitem(last=False)
            # Opportunistic purge of expired
            self._purge_expired_unlocked()

    def delete(self, key: str) -> None:
        with self._lock:
            self._data.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._data.clear()
