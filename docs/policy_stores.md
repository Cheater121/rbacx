# Policy stores

Policy sources implement a single protocol:

```python
from typing import Any, Dict, Optional, Protocol

class PolicySource(Protocol):
    def load(self) -> Dict[str, Any]: ...
    def etag(self) -> Optional[str]: ...
```

Out of the box, three stores are available: **File**, **HTTP**, **S3**.

---

## FilePolicySource (local file)

**Module:** `rbacx.store.file_store` (also re-exported from `rbacx.store`).

### Import & basic usage

```python
from rbacx.store import FilePolicySource

source = FilePolicySource("policy.json")  # path to a JSON file
doc = source.load()                       # policy as a dict
tag = source.etag()                       # string or None
```

### Behavior

- Loads JSON from a local file.
- `etag()` reflects the file content (suitable for change detection).
- If validation is enabled, it performs a schema check via `rbacx.dsl.validate`.

### Constructor options (core)

- `validate_schema: bool = False` — enable schema validation on `load()`.
- `include_mtime_in_etag: bool` - if needed "touch" changes detected (default `False`).

## Safe write utility

```python
from rbacx.store import atomic_write

atomic_write("policy.json", data='{"rules": []}', encoding="utf-8")
```

---

## HTTPPolicySource (HTTP/HTTPS)

**Module:** `rbacx.store.http_store`.
**Extra dependency:** `pip install "rbacx[http]"`.

### Import & basic usage

```python
from rbacx.store.http_store import HTTPPolicySource  # also re-exported from `rbacx.store`.

source = HTTPPolicySource("https://example.com/rbac/policy.json")
doc = source.load()   # dict; if server returns 304 Not Modified — returns {}
tag = source.etag()   # last ETag (if provided by the server)
```

### Behavior

- Issues a GET request and, if a previous ETag is known, sends `If-None-Match`.
- On `304 Not Modified`, returns empty dict `{}` — a signal that applying can be skipped.

### Constructor options (core)

- `headers: dict[str, str] | None = None` — additional HTTP headers.

---

## S3PolicySource

**Module:** `rbacx.store.s3_store` (also re-exported from `rbacx.store`).
**Requires:** `boto3` (and optionally `botocore` for advanced client tuning).

### Import & basic usage

```python
from rbacx.store import S3PolicySource

source = S3PolicySource("s3://my-bucket/policies/rbac.json")
doc = source.load()   # JSON document from S3 as a dict
tag = source.etag()   # string or None (depending on the strategy)
```

### Change-detection strategies

The `change_detector` parameter selects the source of the "change tag":

- `"etag"` (default) — uses ETag from `HeadObject`.
- `"version_id"` — uses `VersionId` (bucket versioning must be enabled).
- `"checksum"` — uses `GetObjectAttributes(..., ObjectAttributes=['Checksum'])` if object checksums are enabled.

If a strategy is unavailable for a particular bucket/object, use `"etag"` (the most compatible option).

### Options (core)

- `validate_schema: bool = False` — validate the policy against the schema on `load()`.

**Network/client parameters:**

- You can pass a prepared `boto3.Session`.
- Timeouts/retries can be tuned via `botocore.config.Config`.
- Additional client parameters are accepted (e.g., `endpoint_url`, `region_name`).

*(Argument names match the `S3PolicySource` constructor; use the simple form from the example if you don't need advanced tuning.)*

---

## Using with HotReloader

Any store can be connected to `HotReloader`:

```python
from rbacx import Guard
from rbacx import HotReloader
from rbacx.store import FilePolicySource, S3PolicySource
from rbacx.store.http_store import HTTPPolicySource

guard = Guard(policy={})

# Local file
file_src = FilePolicySource("policy.json")
HotReloader(guard, file_src, poll_interval=2.0).start()

# HTTP
http_src = HTTPPolicySource("https://example.com/rbac/policy.json")
HotReloader(guard, http_src, poll_interval=5.0).start()

# S3
s3_src = S3PolicySource("s3://my-bucket/policies/rbac.json")
HotReloader(guard, s3_src, poll_interval=5.0).start()
```

It is recommended to begin with an explicit `check_and_reload()` when the process starts, and then either enable background polling with `start()` or call `check_and_reload()` at request boundaries (see `RbacxMiddleware`).
