# Policy loading (hot reload)

RBACX supports hot-reloading policies from external sources via a lightweight reloader.

- A policy source implements the `PolicySource` protocol:
  `load() -> dict` and `etag() -> Optional[str]`.
- The `HotReloader` watches a source: when its ETag changes, it loads the new policy and applies it to a running `Guard`.

---

## When to use

- When you want changes to JSON or dict policies to be picked up without restarting your application.
- When you are using file, HTTP, or S3 backed policy storage and want automatic or manual checking of updates.

---

## Quick example (file)

```python
from rbacx.core.engine import Guard
from rbacx.store import FilePolicySource
from rbacx.policy.loader import HotReloader

# Start with an initial or empty policy
guard = Guard(policy={})

# Local filesystem source
source = FilePolicySource("policy.json")

# Create the hot reloader, with polling interval in seconds
reloader = HotReloader(guard, source, poll_interval=2.0)

# Optional: force a one-time check at startup
reloader.check_and_reload()

# Optional: run background polling
reloader.start()           # uses default poll_interval
# ... your app runs ...
reloader.stop()            # when shutting down
```
---

## HotReloader API

```python
from rbacx.policy.loader import HotReloader
```

### Constructor parameters

| Parameter | Description |
| --- | --- |
| `guard` | instance of `rbacx.core.engine.Guard` to which new policies will be applied. |
| `source` | any `PolicySource` instance (e.g. File, HTTP, S3). |
| `poll_interval: float = 5.0` | default interval in seconds for polling when using `start()`. |

### Methods

- `check_and_reload() -> bool` — synchronously checks the source’s ETag; if changed, loads policy and applies. Returns `True` if a reload occurred, otherwise `False`.
- `start(interval: float | None = None) -> None` — starts background polling. If an `interval` argument is passed, it overrides the one given in the constructor.
- `stop(timeout: float | None = None) -> None` — stops background polling; optionally waits up to `timeout` seconds for current check to finish.

### Diagnostic / properties

HotReloader exposes some properties useful for observability:

- `last_etag` — the most recently seen ETag from the source.
- `last_reload_at` — timestamp (e.g. epoch or datetime) when the last successful reload happened.
- `last_error` — any exception or error encountered during load/etag/check, if present.
- `suppressed_until` — timestamp until which further reload attempts may be suppressed after an error (backoff logic).

### Typical reload cycle

1. Retrieve current ETag from the `PolicySource`.
2. If ETag is new (or `etag()` returns `None` but content changed), call `source.load()`.
3. If `validate_schema` is enabled on source, validate the loaded policy.
4. If load succeeds and policy is valid, apply it to `guard`.
5. If errors occur (parsing, network, permissions), log the error, suppress repeated attempts for a while (backoff), and do not change the active policy.

---

## Integration with web frameworks

### ASGI-middleware & on-request checking option

You may use HotReloader together with middleware to ensure policy changes are checked before handling incoming requests, or rely solely on background polling.

```python
from rbacx.adapters.asgi import RbacxMiddleware
from rbacx.core.engine import Guard
from rbacx.store import FilePolicySource
from rbacx.policy.loader import HotReloader
from litestar import Litestar, get
from litestar.middleware import DefineMiddleware

guard = Guard(policy={})
reloader = HotReloader(guard, FilePolicySource("policy.json"), poll_interval=2.0)

@get("/secure")
def secure() -> dict:
    # guard used automatically via middleware or dependency
    return {"ok": True}

app = Litestar(
    route_handlers=[secure],
    middleware=[DefineMiddleware(RbacxMiddleware, guard=guard, policy_reloader=reloader)],
)
```

Use `reloader.start()` to enable continuous background polling.

If low latency of policy change detection is required, use middleware that calls `check_and_reload()` at the beginning of request processing, or invoke it manually in relevant places.

---

## Supported PolicySource types

HotReloader works with any implementation of `PolicySource`. Out of the box, RBACX provides:

- **FilePolicySource** — local JSON/dict file.
- **HTTPPolicySource** — external HTTP/HTTPS endpoint with ETag support.
- **S3PolicySource** — policies stored in Amazon S3, with configurable change detection.

For details on options and behavior of each, see **Policy stores**.
