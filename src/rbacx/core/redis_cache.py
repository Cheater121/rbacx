"""Redis-backed cache adapter for :class:`rbacx.core.cache.AbstractCache`.

Install the extra to use it:

    pip install "rbacx[cache-redis]"

Example usage::

    import redis
    from rbacx import Guard
    from rbacx.core.redis_cache import RedisCache

    client = redis.Redis(host="localhost", port=6379, db=0)
    guard = Guard(policy, cache=RedisCache(client, prefix="rbacx:", default_ttl=300))

The adapter is intentionally thin:

* Values are serialised with :mod:`json` (not ``pickle``) — safe for the plain
  dicts that the engine stores.
* All Redis operations are wrapped in ``try/except``; a Redis failure is treated
  as a cache miss rather than an authorisation error.
* ``redis-py`` clients are thread-safe by default; no additional locking is
  needed.
* Works with ``redis.Redis``, ``redis.cluster.RedisCluster``, and any
  compatible stub that exposes ``get``, ``set``, ``setex``, ``delete``, and
  ``scan_iter``.
"""

import json
import logging
from typing import Any

logger = logging.getLogger("rbacx.core.redis_cache")


class RedisCache:
    """Redis-backed :class:`~rbacx.core.cache.AbstractCache` implementation.

    Args:
        client: a ``redis.Redis`` (or compatible) client instance.
        prefix: key prefix applied to every cache key to avoid collisions with
            other data in the same Redis database.  Defaults to ``"rbacx:"``.
        default_ttl: fallback TTL in seconds used when :meth:`set` is called
            without an explicit *ttl* argument.  ``None`` means no expiry.

    Notes:
        * Serialisation uses :mod:`json`.  Values must be JSON-serialisable
          (the engine only stores plain dicts, so this is always satisfied).
        * On any Redis error the adapter logs a ``DEBUG`` message and returns
          a safe fallback (``None`` for :meth:`get`, no-op for mutating
          methods).  Cache failures never surface as authorisation errors.
        * :meth:`clear` uses ``SCAN`` to find keys matching the prefix and
          deletes them in batches — it does **not** use ``FLUSHDB``.
    """

    def __init__(
        self,
        client: Any,
        *,
        prefix: str = "rbacx:",
        default_ttl: int | None = None,
    ) -> None:
        self._client = client
        self._prefix = prefix
        self._default_ttl = default_ttl

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _key(self, key: str) -> str:
        return f"{self._prefix}{key}"

    def _serialize(self, value: Any) -> str:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)

    def _deserialize(self, raw: bytes | str | None) -> Any | None:
        if raw is None:
            return None
        try:
            text = raw.decode("utf-8") if isinstance(raw, (bytes, bytearray)) else raw
            return json.loads(text)
        except Exception:
            logger.debug("RedisCache: failed to deserialise value", exc_info=True)
            return None

    # ------------------------------------------------------------------
    # AbstractCache interface
    # ------------------------------------------------------------------

    def get(self, key: str) -> Any | None:
        """Return the cached value for *key*, or ``None`` on miss or error."""
        try:
            raw = self._client.get(self._key(key))
            return self._deserialize(raw)
        except Exception:
            logger.debug("RedisCache.get failed for key %r", key, exc_info=True)
            return None

    def set(self, key: str, value: Any, ttl: int | None = None) -> None:
        """Store *value* under *key* with an optional TTL in seconds.

        TTL precedence: explicit *ttl* argument → :attr:`default_ttl` → no expiry.
        """
        effective_ttl = ttl if ttl is not None else self._default_ttl
        try:
            serialised = self._serialize(value)
            rkey = self._key(key)
            if effective_ttl is not None and effective_ttl > 0:
                self._client.setex(rkey, effective_ttl, serialised)
            else:
                self._client.set(rkey, serialised)
        except Exception:
            logger.debug("RedisCache.set failed for key %r", key, exc_info=True)

    def delete(self, key: str) -> None:
        """Remove a single key from Redis."""
        try:
            self._client.delete(self._key(key))
        except Exception:
            logger.debug("RedisCache.delete failed for key %r", key, exc_info=True)

    def clear(self) -> None:
        """Delete all keys matching this adapter's prefix.

        Uses ``SCAN`` with a glob pattern — never ``FLUSHDB``.  Safe to call
        on a shared Redis instance.
        """
        pattern = f"{self._prefix}*"
        try:
            keys = list(self._client.scan_iter(pattern))
            if keys:
                self._client.delete(*keys)
        except Exception:
            logger.debug("RedisCache.clear failed (pattern=%r)", pattern, exc_info=True)


__all__ = ["RedisCache"]
