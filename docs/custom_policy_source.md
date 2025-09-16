# Creating a Custom `PolicySource` (concise + best practices)

RBACX accepts any object that implements the `PolicySource` protocol:

```python
class PolicySource(Protocol):
    def load(self) -> Dict[str, Any]: ...
    def etag(self) -> Optional[str]: ...
```

**Built-ins:** File, HTTP, and S3 sources already ship with RBACX. This page keeps **one small example** (in‑memory) and focuses on **how to design your own** source robustly.

---

## Minimal in‑memory source

```python
from typing import Any, Dict, Optional
from rbacx import HotReloader, Guard

class MemorySource:
    def __init__(self, policy: Dict[str, Any], etag: str = "v1"):
        self._policy = policy
        self._etag = etag

    def etag(self) -> Optional[str]:
        # Return a cheap, stable version for the current policy
        return self._etag

    def load(self) -> Dict[str, Any]:
        # Return a dict representing a Policy or PolicySet
        return self._policy

# Usage
guard = Guard(policy={"rules": []})
src = MemorySource(policy={
    "rules": [
        {"id": "allow_read", "actions": ["read"], "resource": {"type": "doc"}, "effect": "permit"}
    ]
}, etag="v2")
reloader = HotReloader(guard, src, initial_load=True)  # loads immediately when etag differs
```

---

## Design guidelines (what good sources do)

- **Cheap/stable versioning via `etag()`**
  - Return a value that changes **only** when the policy changes (hash, version id, last‑modified, etc.).
  - Prefer values that your backend already guarantees (e.g. HTTP `ETag`, S3 `VersionId`). If not available, compute one (e.g. hash) in `load()` and cache it.

- **Deterministic `load()`**
  - Always return a fully parsed **`dict`** (Policy or PolicySet), never partially filled structures.
  - Validate input if you transform from YAML → JSON, and fail fast on invalid schema.

- **Resilience & fairness**
  - For remote backends: use **timeouts**, **retries**, **exponential backoff with jitter**, and a **max backoff cap**.
  - Surface meaningful exceptions in logs; don’t swallow permanent errors.

- **Integrity & security**
  - Verify payload integrity when possible (signed artifact, checksum, or versioned objects).
  - Secure transport: TLS; consider **mTLS / pinning** for internal services.

- **Sensible defaults**
  - If `etag()` can’t be computed upfront, return `None`; `HotReloader` will still call `load()` when forced or on scheduled runs.
  - Keep `load()` side‑effect free (no writes).

---

## Operational tips

- **Polling**: Pick an interval that fits your update cadence; add small random jitter to reduce thundering herds.
- **Observability**: Log failures with context (source, attempt, delay), add metrics (reload success/failure, last apply time).
- **Circuit‑breakers**: If your backend is unstable, short‑circuit after N attempts and try later.
- **Rollouts**: Version your policies; keep a quick rollback path (e.g., previous VersionId/artifact).

---

## Testing your source

- **Unit**: Prove `etag()` stability for no‑change scenarios; verify change detection and that `load()` rejects malformed data.
- **Integration**: Exercise `HotReloader.check_and_reload(force=True)` and the background `start()/stop()` loop.
- **Failure modes**: Simulate timeouts/5xx and ensure backoff+jitter take effect and logs are clear.

---

## Checklist

- [ ] `etag()` returns a cheap, stable value that changes only when policy changes (or `None` if unknown).
- [ ] `load()` returns a valid **dict** (Policy/PolicySet).
- [ ] Remote backends: timeouts, retries, **exponential backoff with jitter**, max cap.
- [ ] Integrity/security measures in place (versioning, checksums, signatures, TLS/mTLS).
- [ ] Good logs/metrics for visibility; clear rollback path.
