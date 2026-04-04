# Decision Caching

Decision caching speeds up repeated authorization checks by storing final `Guard` decisions for a short time (TTL). This reduces latency and load on your policy and attribute sources, especially for “hot” endpoints. Caching is **optional** and configured per `Guard` instance.

---

## Current capabilities

- **Optional, per-Guard.** Caching is disabled by default; you enable it explicitly in the `Guard` constructor.
- **Pluggable interface.** Any implementation compatible with `AbstractCache` can be used; a simple in-memory **LRU+TTL** implementation is available for single-process scenarios.
- **TTL on write.** Controlled with the `cache_ttl` parameter (seconds).
- **Automatic invalidation on policy updates.** When the policy changes, the cache is cleared to avoid serving decisions produced by outdated rules.
- **Manual clear.** Use `guard.clear_cache()` to purge cached decisions proactively.

> Note: the in-memory cache works **within a single process/worker**. For multi-process or distributed deployments use `RedisCache` (see below) or another external cache implementation.

---

## Quick start

### Enable caching

```python
from rbacx import Action, Context, Guard, Subject, Resource
from rbacx.core.cache import DefaultInMemoryCache

policy = {
    "algorithm": "deny-overrides",
    "rules": [
        {
            "id": "doc_read",
            "effect": "permit",
            "actions": ["read"],
            "resource": {"type": "doc", "attrs": {"visibility": ["public", "internal"]}},
            "roles": ["reader", "admin"],   # shorthand for hasAny on subject.roles
            # equivalent (legacy syntax):
            # "condition": {"hasAny": [ {"attr": "subject.roles"}, ["reader", "admin"] ]},
            "obligations": [ {"type": "require_mfa"} ]
        },
        {"id": "doc_deny_archived", "effect": "deny", "actions": ["*"],
         "resource": {"type": "doc", "attrs": {"archived": True}}}
    ],
}

default_cache = DefaultInMemoryCache(maxsize=2048)
guard = Guard(
    policy=policy,
    cache=default_cache,           # in-memory LRU for single-process setups
    cache_ttl=300,                 # decision TTL in seconds
)

decision = guard.evaluate_sync(
    subject=Subject(id="u1", roles=["reader"]),
    action=Action("read"),
    resource=Resource(type="doc", id="42", attrs={"visibility": "public"}),
    context=Context(attrs={"mfa": True}),
)

# Manual cache purge if needed:
guard.clear_cache()
```

### When it clears automatically
- On **policy updates** via the core API, to avoid serving decisions based on old rules.

---

## Redis cache adapter

For multi-process or multi-host deployments use `RedisCache` from
`rbacx.core.redis_cache`.  Install the extra first:

```bash
pip install "rbacx[cache-redis]"
```

```python
import redis
from rbacx import Guard
from rbacx.core.redis_cache import RedisCache

client = redis.Redis(host="localhost", port=6379, db=0)

guard = Guard(
    policy=policy,
    cache=RedisCache(
        client,
        prefix="rbacx:",  # key prefix — avoids collisions with other data
        default_ttl=300,  # seconds; can be overridden per set() call
    ),
)
```

### TTL precedence

1. Explicit `ttl` passed by `Guard` via `cache.set(key, value, ttl=N)` — wins
2. `default_ttl` set on `RedisCache(...)` — fallback
3. No TTL — key never expires

### Behaviour on Redis failures

All operations (`get`, `set`, `delete`, `clear`) catch exceptions and log them
at `DEBUG` level.  A Redis outage is treated as a cache miss — authorisation
decisions are still computed correctly, just without the cache speedup.

### Notes

- Serialisation uses `json` (not `pickle`) — safe and auditable.
- `clear()` uses `SCAN` with a prefix glob — never `FLUSHDB`.  Safe to call on
  a shared Redis instance.
- `redis-py` clients are thread-safe by default; no additional locking is
  needed.
- Works with `redis.Redis`, `redis.cluster.RedisCluster`, and any compatible
  client that implements `get`, `set`, `setex`, `delete`, and `scan_iter`.

---

## Implementing your own cache

A custom cache must conform to the `AbstractCache` protocol. Below is a description of what each method is expected to do (no external dependencies, no specific backend implied):

- **`get(key: str) -> Optional[Any]`**
  Return the stored decision for the given key, or `None` if the entry is missing or expired.
  The key is an **opaque string** produced by `Guard`; do not parse or reinterpret it.

- **`set(key: str, value: Any, ttl: Optional[int]) -> None`**
  Store the decision for the key and **honor the TTL** (seconds). If TTL is missing or non-positive, treat it as “no expiration” or follow your implementation’s policy.
  Ensure the value you store can be returned as-is by `get`.

- **`clear() -> None`**
  Clear all entries for the current instance/namespace. The core uses this during policy replacement and for explicit manual clears.

- *(optional)* **`delete(key: str)` / `invalidate(key: str)`**
  Targeted invalidation for a single key. Not required by the core (which relies on `clear()` and TTL), but may be useful in your environment.

### Implementation notes (to remain stable over time)

- **Resilience.** Cache errors must not break authorization. On failures, behave as if there’s a miss (`get` returns `None`; `set/clear` swallow transient errors).
- **Always respect TTL.** TTL is the guardrail against stale decisions lingering indefinitely.
- **Treat keys as a black box.** Do not add semantics or derive data from keys. This keeps the cache robust to future key format changes.
- **Data safety.** Avoid placing sensitive data into keys or metadata, and be mindful of your infrastructure’s visibility (logs, monitors, dumps).
- **Scaling.** For distributed backends, use stable serialization and predictable TTL semantics.
- **Stampede mitigation.** For “hot” keys, consider small TTL jitter or a “serve stale then revalidate” approach to avoid synchronized expirations.
- **Optional observability.** If feasible, expose simple hit/miss and size indicators to tune TTL and capacity.
- **Strict mode.** With `strict_types=True`, the engine injects `__strict_types__` into the env, so cache keys differ from lax mode. See [Types](types.md).
- **Explain mode.** With `explain=True`, the engine injects `__explain__` into the env, so cache keys for traced evaluations differ from non-traced ones.  A cached non-traced result will not be served for a traced request and vice versa, ensuring `Decision.trace` is always consistent with the flags passed.

---

## Best practices (what to watch for)

- **Prefer short TTLs for authorization.** Rights and attributes change; short TTLs reduce the desynchronization window.
- **Invalidate on policy change.** The core already performs automatic clearing — keep it enabled.
- **Do not rely on the cache for correctness.** Decisions must be computed correctly without a cache; caching is an optimization only.
- **Mitigate cache stampedes.** Use TTL jitter and/or serve-stale-then-revalidate for hot keys; avoid synchronized expiry of many entries at once.
- **Be cautious with negative caching.** Caching `deny` improves load but may widen the “false deny” window immediately after granting new rights.
- **Scope & safety.** In-memory cache scope is a single process; external caches require proper access controls and data lifecycle policies.
