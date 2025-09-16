# Creating a Custom `PolicySource`

This guide shows how to implement your own **PolicySource** for RBACX (e.g., HTTP, DB, Redis, S3, etc.), and how to plug it into the hot reloader.

> **Contract (Protocol)** — a `PolicySource` exposes two methods:
>
> ```python
> class PolicySource(Protocol):
>     def load(self) -> Dict[str, Any]: ...
>     def etag(self) -> Optional[str]: ...
> ```
>
> - `etag()` must return a **stable identifier** for the *current* policy version (e.g., file hash, HTTP `ETag`, DB version). It can return `None` if your source cannot compute one up front.
> - `load()` must return a **Policy or PolicySet** as a Python `dict` (parsed JSON). If `etag()` changes, RBACX will call `load()` and apply the new policy via `HotReloader`.

See: `rbacx.core.ports.PolicySource` and `rbacx.policy.loader.HotReloader`.

---

## Quick start: minimal in-memory source

```python
from typing import Any, Dict, Optional
from rbacx import HotReloader, Guard

class MemorySource:
    def __init__(self, policy: Dict[str, Any], etag: str = "v1"):
        self._policy = policy
        self._etag = etag

    def etag(self) -> Optional[str]:
        return self._etag

    def load(self) -> Dict[str, Any]:
        return self._policy

# Usage
guard = Guard(policy={"rules": []})  # initial
src = MemorySource(policy={"rules": [{"id":"allow","actions":["read"],"resource":{"type":"doc"},"effect":"permit"}]}, etag="v2")
reloader = HotReloader(guard, src, initial_load=True)  # does an immediate load when etag differs
```

---

## Recommended design rules (high-level)

1. **Return a strong “version” from `etag()` and keep it cheap.**
   - For **HTTP**, reuse the server’s `ETag` and conditional requests (`If-None-Match`) on your side if you’re doing your own polling; HTTP semantics are standardized in RFC 9110. citeturn0search4
   - For **S3**, beware: the S3 `ETag` is **not always MD5** for multipart uploads; prefer **`VersionId`** (if buckets are versioned) or your own checksum. citeturn0search1turn0search5turn0search21
2. **Make `load()` deterministic and validate JSON** before returning (you can call `rbacx validate` separately during CI).
3. **Be resilient**: use **timeouts**, **retries**, and **exponential backoff with jitter** for remote sources to avoid thundering herds. citeturn0search6turn0search2
4. **Secure transport**: use TLS, consider **mTLS / pinning** for internal services; verify checksums when possible.
5. **Keep the schema stable**: Follow the documented policy format (`rules` / `policies`, `actions`, `resource.type`, `resource.attrs`).

---

## Example: File-based source (hash + mtime)

```python
import json, hashlib, os
from typing import Any, Dict, Optional

class FilePolicySource:
    def __init__(self, path: str):
        self._path = path

    def etag(self) -> Optional[str]:
        try:
            st = os.stat(self._path)
            # Combine size+mtime to avoid reading the file on every poll.
            return f"{int(st.st_mtime_ns)}-{st.st_size}"
        except OSError:
            return None  # let HotReloader attempt load()

    def load(self) -> Dict[str, Any]:
        with open(self._path, "rb") as f:
            data = f.read()
        # Optional stronger tag: hash of contents (more expensive).
        # self._etag_cache = hashlib.sha256(data).hexdigest()
        return json.loads(data.decode("utf-8"))
```

**When to use content-hash vs. metadata:** if the file is large / polled often, prefer metadata-derived `etag()` and compute a hash only inside `load()` on change detection.

---

## Example: HTTP source (ETag + If-None-Match)

```python
import json, urllib.request
from typing import Any, Dict, Optional

class HttpPolicySource:
    def __init__(self, url: str, timeout: float = 5.0):
        self._url = url
        self._timeout = timeout
        self._etag: Optional[str] = None

    def etag(self) -> Optional[str]:
        # Use a cheap HEAD probe to read ETag if your endpoint supports it;
        # else keep the last seen ETag from GET.
        return self._etag

    def load(self) -> Dict[str, Any]:
        req = urllib.request.Request(self._url, method="GET")
        if self._etag:
            req.add_header("If-None-Match", self._etag)
        with urllib.request.urlopen(req, timeout=self._timeout) as resp:
            if resp.status == 304:  # Not Modified
                raise RuntimeError("No change detected; loader should not call load() without etag change")
            new_etag = resp.headers.get("ETag")
            body = resp.read().decode("utf-8")
            policy = json.loads(body)
        if new_etag:
            self._etag = new_etag
        return policy
```

- `ETag` and conditional requests (`If-None-Match`) are part of HTTP’s caching model; use them when your policy endpoint supports it. citeturn0search4turn0search12turn0search24

> Tip: If your endpoint cannot serve `ETag`, expose a **version field**, **hash**, or **monotonic integer**; return it from `etag()`.

---

## Example: Amazon S3 source (VersionId-aware)

```python
import json
from typing import Any, Dict, Optional
try:
    import boto3  # optional
except Exception:  # pragma: no cover
    boto3 = None  # type: ignore

class S3PolicySource:
    def __init__(self, bucket: str, key: str, s3_client=None):
        self._bucket = bucket
        self._key = key
        self._s3 = s3_client or (boto3 and boto3.client("s3"))
        self._version: Optional[str] = None  # prefer VersionId; ETag can be misleading

    def etag(self) -> Optional[str]:
        if not self._s3:
            return None
        resp = self._s3.head_object(Bucket=self._bucket, Key=self._key)
        # Prefer VersionId when bucket versioning is enabled; fall back to ETag otherwise.
        return resp.get("VersionId") or resp.get("ETag")

    def load(self) -> Dict[str, Any]:
        if not self._s3:
            raise RuntimeError("boto3 not installed")
        resp = self._s3.get_object(Bucket=self._bucket, Key=self._key, VersionId=self._version)
        body = resp["Body"].read().decode("utf-8")
        self._version = resp.get("VersionId") or resp.get("ETag")
        return json.loads(body)
```

Why not rely solely on S3 `ETag`? For multipart uploads, the `ETag` **is not a true MD5 of the full object** and should not be used as an integrity check; if you need integrity, use checksums or VersionId. citeturn0search1turn0search5turn0search21

---

## Plug into the reloader

```python
from rbacx import Guard, HotReloader

guard = Guard(policy={"rules": []})
source = HttpPolicySource("https://policies.example.com/current.json")
rld = HotReloader(guard, source, initial_load=True, poll_interval=5.0)
rld.start()           # background polling
# ...
rld.stop()
```

The `HotReloader`:
- calls `source.etag()`; if it changed, calls `source.load()` and then `guard.set_policy(...)`;
- supports synchronous `.check_and_reload()` and a background `.start()/stop()` loop with jitter/backoff.

> **Why Protocols?** RBACX uses Python’s `typing.Protocol` (PEP 544) so your custom class is accepted if it **structurally** matches the required methods — no inheritance needed. citeturn0search7turn0search11

---

## Operational tips

- Use **timeouts and capped exponential backoff with jitter** for remote calls. citeturn0search6turn0search2turn0search22
- Log failures at **warning/error** level with context (source, attempt, delay).
- Consider **signature verification** (e.g., signed policy artifacts) or **TLS client auth** for internal endpoints.
- If you down-convert from YAML → JSON, validate against the RBACX schema and reject on error.
- For HTTP: prefer **`If-None-Match`** over polling entire payloads; a 304 short-circuit saves bandwidth and reduces latency. citeturn0search12

---

## Testing your source

- Unit test `etag()` stability for **no-change** scenarios and change detection on updates.
- Unit test `load()` error handling (timeouts, non-JSON, 5xx).
- Integration test with `HotReloader.check_and_reload(force=True)` and background `start()/stop()`.

**Example pytest snippet**

```python
def test_custom_source_integration(monkeypatch):
    guard = Guard(policy={"rules": []})

    # Fake source that toggles etag after first call
    class Src:
        def __init__(self): self.i = 0
        def etag(self): self.i += 1; return "v2" if self.i > 1 else "v1"
        def load(self): return {"rules":[{"id":"p","actions":["read"],"resource":{"type":"doc"},"effect":"permit"}]}

    rld = HotReloader(guard, Src(), initial_load=False)
    changed = rld.check_and_reload(force=True)  # first load
    assert changed is True
```

---

## Checklist

- [ ] `etag()` returns a stable, cheap version string (or `None` if unknown).
- [ ] `load()` returns **valid JSON dict** of a Policy/PolicySet.
- [ ] Remote sources: timeouts, retries, **backoff with jitter**, and secure transport. citeturn0search6
- [ ] Prefer **VersionId** over `ETag` for S3 buckets with versioning. citeturn0search21
- [ ] Document the source’s **failure modes** and monitoring (metrics/logging).
