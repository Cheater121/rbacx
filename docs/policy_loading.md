
# Policy loading (hot reload)

RBACX supports hot-reloading policies from external sources via a production-grade reloader.

- A policy source implements the `PolicySource` protocol:
  `load() -> dict` and `etag() -> Optional[str]`.
- The `HotReloader` watches a source: when its ETag changes, it loads the new policy and applies it to a running `Guard`. (If `etag()` returns `None`, the reloader will attempt a load and let the source decide change detection.) ETag is a standard content version identifier in HTTP and storage systems.

---

## When to use

- You want changes to JSON or dict policies to be picked up **without restarting** your application.
- You use file/HTTP/S3 (or any custom) policy storage and want **automatic** or **manual** checks for updates.
- You want resilient reloads with **exponential backoff + jitter** after errors to avoid thundering herds.

---

## Quick examples

### 1) Safe startup (recommended)
Ensures a valid policy is loaded at boot, then enables background polling.

```python
from rbacx.core.engine import Guard
from rbacx.store import FilePolicySource
from rbacx.policy.loader import HotReloader

guard = Guard(policy={})
source = FilePolicySource("policy.json")

reloader = HotReloader(guard, source, initial_load=True, poll_interval=2.0)

# Synchronously load whatever is in policy.json right now
reloader.check_and_reload()        # returns True on first load

# Then keep watching for changes in the background
reloader.start()
# ...
reloader.stop()
```

### 2) Legacy behavior (no initial load)
First check is a NO-OP unless the policy changes (backwards-compatible default).

```python
reloader = HotReloader(guard, source, initial_load=False)
reloader.check_and_reload()        # likely False until ETag changes
```

### 3) Force a one-time load (ignore ETag)
Useful for bootstrap/migrations.

```python
reloader = HotReloader(guard, source)
reloader.check_and_reload(force=True)
```

### 4) Force initial load via `start()`
Performs a synchronous load before the thread starts.

```python
reloader = HotReloader(guard, source, initial_load=False)
reloader.start(initial_load=True, force_initial=True)
```

Steps:
1) Start with an initial or empty policy  
2) Choose source (Local filesystem in examples)  
3) Create the reloader (optionally enable `initial_load`)  
4) Optional: force a one-time check at startup  
5) Optional: run background polling  
6) Your app runs between `start()` and `stop()`  

---

## HotReloader API

```python
from rbacx.policy.loader import HotReloader
```

### Constructor parameters

| Parameter | Description |
| --- | --- |
| `guard` | The `rbacx.core.engine.Guard` instance to update. |
| `source` | Any `PolicySource` (File, HTTP, S3, custom, вЂ¦). |
| `initial_load: bool = False` | If `True`, **do not** prime the ETag so the **first** `check_and_reload()` will load the current policy. If `False` (default), the first check is a NO-OP unless the ETag changed (legacy behavior). |
| `poll_interval: float = 5.0` | Default polling interval (seconds) used by `start()`. |

### Methods

- `check_and_reload(*, force: bool = False) -> bool`  
  Synchronously checks the sourceвЂ™s ETag; if changed, loads and applies the policy.  
  If `force=True`, loads and applies **regardless** of ETag. Returns `True` if a reload occurred.

- `start(interval: float | None = None, *, initial_load: bool | None = None, force_initial: bool = False) -> None`  
  Starts background polling.  
  - `interval` overrides the constructorвЂ™s `poll_interval`.  
  - `initial_load` overrides the constructorвЂ™s flag **just for this start**.  
  - If `initial_load` is truthy and `force_initial=True`, performs a synchronous load before starting the thread (ETag ignored for that initial load).

- `stop(timeout: float | None = None) -> None`  
  Stops background polling; optionally waits up to `timeout` seconds for the current check.

### Diagnostics / properties

- `last_etag` вЂ” most recently seen ETag from the source.  
- `last_reload_at` вЂ” timestamp of the last successful reload.  
- `last_error` вЂ” the last exception encountered (if any).  
- `suppressed_until` вЂ” time until which further attempts are delayed after errors (exponential backoff with jitter).

---

## Typical reload cycle

1. Ask the `PolicySource` for its current ETag.  
2. If the ETag is new (or `etag()` is `None`), call `load()` to fetch the policy.  
3. Validate (if the source performs schema checks).  
4. Apply the policy to `guard` **only after a successful load**.  
5. On errors (parse, network, permissions), keep the **previous working** policy, log the error, and schedule the next attempt using exponential backoff with jitter.

---

## Integration with web frameworks

### ASGI middleware & on-request checks

Use `HotReloader` with your middleware to check for changes before handling requests, or rely solely on background polling.

```python
from rbacx.adapters.asgi import RbacxMiddleware
from rbacx.core.engine import Guard
from rbacx.store import FilePolicySource
from rbacx.policy.loader import HotReloader
from litestar import Litestar, get
from litestar.middleware import DefineMiddleware

guard = Guard(policy={})
reloader = HotReloader(guard, FilePolicySource("policy.json"), initial_load=True, poll_interval=2.0)
reloader.check_and_reload()  # ensure policy is present at startup

@get("/secure")
def secure() -> dict:
    # guard used automatically via middleware or dependency
    return {"ok": True}

app = Litestar(
    route_handlers=[secure],
    middleware=[DefineMiddleware(RbacxMiddleware, guard=guard, policy_reloader=reloader)],
)
```

If you need ultra-low detection latency, call `reloader.check_and_reload()` at the beginning of request handling (cheap ETag check), or keep background polling short.

---

## Supported `PolicySource` types

Out of the box, RBACX provides:

- **FilePolicySource** вЂ” local JSON file or dict snapshot.
- **HTTPPolicySource** вЂ” HTTP/HTTPS endpoint (ideal with ETag or Last-Modified validators).
- **S3PolicySource** вЂ” Amazon S3 objects with ETag-based change detection.

Any custom source that implements `load()` and `etag()` is supported.

---

## Operational guidance

- **Atomic writes** (file sources): write to a temp file and `rename` to avoid readers seeing partial content.  
- **Backoff & jitter**: on repeated failures, use exponential backoff **with jitter**; this avoids synchronized retries and thundering herds. RBACXвЂ™s reloader applies jitter by default.  
- **Observability**: export metrics/counters for reload successes/failures and `last_reload_at`.  
- **Fail-safe policy**: keep the last known good policy if a new load fails.  
- **Security defaults**: default-deny policies are recommended until the first valid policy is loaded.

---

## Deprecated API

- `ReloadingPolicyManager` is **deprecated** and kept only for compatibility. Constructing it emits a `DeprecationWarning` and a log warning; it delegates to `HotReloader` with legacy semantics (`initial_load=False`). Please migrate to `HotReloader`.
- `PolicyManager` from `rbacx.store.manager` is **deprecated**; use `HotReloader` (plus a `PolicySource` such as `FilePolicySource`) instead.

---

## Changelog (excerpt)

- `HotReloader(..., initial_load: bool = False)` вЂ” new flag to control startup behavior.  
- `check_and_reload(force: bool = False)` вЂ” new `force` parameter to bypass ETag.  
- `start(..., initial_load: bool | None = None, force_initial: bool = False)` вЂ” optional synchronous load before the polling thread starts.  
- `ReloadingPolicyManager` and `rbacx.store.manager.PolicyManager` вЂ” **deprecated**; use `HotReloader`.
