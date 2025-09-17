# Creating a Custom `PolicySource` (concise + best practices)

RBACX accepts any object that implements the `PolicySource` protocol:

```python
class PolicySource(Protocol):
    def load(self) -> Dict[str, Any] | Awaitable[Dict[str, Any]]: ...
    def etag(self) -> Optional[str] | Awaitable[Optional[str]]: ...
```

**Built-ins:** File, HTTP (sync), and S3 (sync) sources already ship with RBACX. But you can write your own — including **async** sources. This page keeps **one small example** (in-memory) and focuses on **how to design your own** source robustly.

---

## Minimal in-memory source

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

* **Cheap/stable versioning via `etag()`**

  * Return a value that changes **only** when the policy changes (hash, version id, last-modified, etc.).
  * Prefer values your backend already guarantees (e.g., HTTP `ETag`, S3 `VersionId`). If not available, compute one (e.g., hash) in `load()` and cache it. For HTTP, `ETag` and conditional requests (`If-None-Match` → `304 Not Modified`) minimize transfer and are standard practice.

* **Deterministic `load()`**

  * Always return a fully parsed **`dict`** (Policy or PolicySet), never partially filled structures.
  * Validate input if you transform from YAML → JSON, and fail fast on invalid schema.

* **Resilience & fairness**

  * For remote backends: use **timeouts**, **retries**, **exponential backoff with jitter**, and a **max backoff cap**.
  * Surface meaningful exceptions in logs; don’t swallow permanent errors.

* **Integrity & security**

  * Verify payload integrity when possible (signed artifact, checksum, or versioned objects).
  * Secure transport: TLS; consider **mTLS / pinning** for internal services.
  * For HTTP caches/validators, see HTTP semantics (RFC 9110) for strong/weak validators and conditional requests. 

* **Sensible defaults**

  * If `etag()` can’t be computed upfront, return `None`; `HotReloader` will still call `load()` when forced or on scheduled runs.
  * Keep `load()` side-effect free (no writes).

---

## Async sources with `httpx` (example)

RBACX’s `HotReloader` supports both sync **and async** `PolicySource` implementations. Below is a production-style **async** HTTP source using `httpx`:

* Uses `httpx.AsyncClient` with explicit **timeouts**. Default HTTPX timeouts are \~5s of inactivity; set your own per your SLOs. 
* Supports **ETag** caching and conditional GET via `If-None-Match` to receive `304 Not Modified` when the policy hasn’t changed. 
* Implements **capped exponential backoff with jitter** on transient failures — no extra dependencies.

```python
import asyncio
import json
import math
import random
from typing import Any, Dict, Optional

import httpx  # pip install httpx

class AsyncHTTPPolicySource:
    """
    Async PolicySource that fetches a JSON policy from an HTTP endpoint.

    - Caches ETag and last good policy in-memory.
    - Uses conditional requests (If-None-Match) to avoid re-downloading unchanged payloads.
    - Applies capped exponential backoff with jitter on transient errors.
    """

    def __init__(
        self,
        url: str,
        *,
        timeout: float = 5.0,
        max_retries: int = 3,
        backoff_base: float = 0.5,
        backoff_cap: float = 8.0,
        http2: bool = False,
        verify: bool | str = True,
    ) -> None:
        self._url = url
        self._timeout = timeout
        self._max_retries = max_retries
        self._backoff_base = backoff_base
        self._backoff_cap = backoff_cap
        self._etag: Optional[str] = None
        self._cached_policy: Optional[Dict[str, Any]] = None
        self._client = httpx.AsyncClient(http2=http2, verify=verify)

    async def close(self) -> None:
        await self._client.aclose()

    # ---- PolicySource API -------------------------------------------------

    async def etag(self) -> Optional[str]:
        # If we've seen an ETag before, return it cheaply.
        if self._etag is not None:
            return self._etag
        # Otherwise, try to fetch headers via a HEAD; fallback to GET if HEAD not allowed.
        try:
            r = await self._client.head(self._url, timeout=self._timeout)
            if r.status_code == 405:  # Method Not Allowed -> fall back to GET headers
                r = await self._client.get(self._url, headers={"Range": "bytes=0-0"}, timeout=self._timeout)
            r.raise_for_status()
            et = r.headers.get("ETag")
            if et:
                self._etag = et
            return self._etag
        except Exception:
            # If anything fails, signal unknown etag; the reloader can still force-load.
            return None

    async def load(self) -> Dict[str, Any]:
        """
        Fetch and parse the policy JSON. Uses If-None-Match to avoid full body when unchanged.
        Retries transient failures with capped exponential backoff + jitter.
        """
        last_etag = self._etag
        headers = {"Accept": "application/json"}
        if last_etag:
            headers["If-None-Match"] = last_etag

        attempt = 0
        while True:
            try:
                r = await self._client.get(self._url, headers=headers, timeout=self._timeout)
                # 304: unchanged -> return cached policy if available
                if r.status_code == 304 and self._cached_policy is not None:
                    return self._cached_policy

                r.raise_for_status()
                # Success path: parse JSON, update cache + etag
                policy = r.json()
                if not isinstance(policy, dict):
                    raise ValueError("policy must be a JSON object")
                self._etag = r.headers.get("ETag", self._etag)
                self._cached_policy = policy
                return policy

            except (httpx.ConnectError, httpx.ReadTimeout, httpx.RemoteProtocolError, httpx.HTTPStatusError) as e:
                # Retry on common transient network/protocol errors and 5xx responses
                if isinstance(e, httpx.HTTPStatusError) and (400 <= e.response.status_code < 500) and e.response.status_code != 429:
                    # Non-retryable 4xx (except 429)
                    raise
                attempt += 1
                if attempt > self._max_retries:
                    raise
                # Exponential backoff with full jitter
                base = self._backoff_base * (2 ** (attempt - 1))
                sleep_s = min(self._backoff_cap, base) * random.uniform(0.0, 1.0)
                await asyncio.sleep(sleep_s)
```

> **Notes**
>
> * HTTP semantics for ETags and conditional requests: MDN (`ETag`, `If-None-Match`, `304`) and RFC 9110 are the authoritative references. 
> * HTTPX async client, timeouts, and options (e.g., `http2`, `verify`): see official docs. 
> * Backoff with **jitter** is recommended to avoid retry storms. 

### Using it with the reloader

```python
from rbacx import Guard, HotReloader

guard = Guard(policy={"rules": []})
src = AsyncHTTPPolicySource("https://policies.example.com/current.json", http2=True, timeout=3.0)

# One-shot (sync), even inside an async app:
changed = HotReloader(guard, src).check_and_reload(force=True)  # the reloader handles event loop bridging

# Or async:
# changed = await HotReloader(guard, src).check_and_reload_async(force=True)
```

**Cleanup:** If you construct long-lived sources, remember to close the `AsyncClient` when done:

```python
await src.close()
```

---

## Operational tips

* **Polling**: Pick an interval that fits your update cadence; add small random jitter to reduce thundering herds. For HTTP, prefer conditional requests so unchanged policies return `304 Not Modified`. 
* **Observability**: Log failures with context (source, attempt, delay), add metrics (reload success/failure, last apply time).
* **Circuit-breakers**: If your backend is unstable, short-circuit after N attempts and try later.
* **Rollouts**: Version your policies; keep a quick rollback path (e.g., previous `VersionId` / artifact).

---

## Testing your source

* **Unit**: Prove `etag()` stability for no-change scenarios; verify change detection and that `load()` rejects malformed data.
* **Integration**: Exercise `HotReloader.check_and_reload(force=True)` and the background `start()/stop()` loop.
* **Failure modes**: Simulate timeouts/5xx and ensure backoff+jitter take effect and logs are clear. AWS guidance on timeouts/retries/jitter is a good reference. 

---

## Checklist

* [ ] `etag()` returns a cheap, stable value that changes only when policy changes (or `None` if unknown).
* [ ] `load()` returns a valid **dict** (Policy/PolicySet).
* [ ] Remote backends: timeouts, retries, **exponential backoff with jitter**, max cap.
* [ ] Integrity/security measures in place (versioning, checksums, signatures, TLS/mTLS).
* [ ] Good logs/metrics for visibility; clear rollback path.

