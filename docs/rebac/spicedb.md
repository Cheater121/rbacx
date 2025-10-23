# SpiceDB / Authzed Provider

Install: `pip install "rbacx[rebac-spicedb]"`

```python
from rbacx.rebac.spicedb import SpiceDBChecker, SpiceDBConfig

cfg = SpiceDBConfig(
    endpoint="localhost:50051",  # gRPC endpoint
    insecure=True,               # plaintext gRPC for local/dev; use TLS in prod
    token=None,                  # optional Bearer token (Authorization: Bearer <token>)
    deadline_ms=200,             # optional per-check deadline
)

checker = SpiceDBChecker(cfg)    # sync by default; optional async if available
```

* Uses gRPC **PermissionService.CheckPermission**; a check is permitted when `permissionship == PERMISSIONSHIP_HAS_PERMISSION`.
* Supports **bulk evaluations** via **CheckBulkPermissions** to reduce round-trips.
* Sync by default; **async mode** can be used **if** your environment provides an async client (e.g., `authzed` async stubs). Otherwise, use the sync client.

See `deploy/compose/spicedb/` for a local Docker Compose and `deploy/compose/spicedb/demo.py`.
For general Docker install docs, see the official guide.

---

## Configuration notes

* **Consistency**
  You can request consistency using a **ZedToken** (`at_least_as_fresh`) or force **`fully_consistent=True`**. Prefer ZedTokens for better cache hit rates and lower latency where possible.

* **Context & caveats**
  ReBAC **context** is forwarded to SpiceDB as a `google.protobuf.Struct`, enabling evaluation of **caveats** defined in your schema.

* **TLS vs insecure**
  `insecure=True` uses a plaintext (non-TLS) channel (suitable for local Docker/CI) and a raw Bearer token; otherwise, use a TLS client with bearer credentials for production.

* **Async client (optional)**
  If your installed `authzed` client exposes async stubs, the checker can operate asynchronously; note that some insecure-channel variants may have limitations around async transports.

---

## Batch Check

When checking many `(subject, relation/permission, resource)` tuples, the checker uses **CheckBulkPermissions** in one call:

```python
pairs = [
    ("user:alice", "viewer", "document:doc1"),
    ("user:alice", "editor", "document:doc1"),
    ("user:alice", "owner",  "document:doc1"),
]

results: list[bool] = checker.batch_check(pairs)
# results[i] corresponds to pairs[i] and is True iff permissionship == HAS_PERMISSION
```

Use a single **ZedToken** across a batch/flow for consistent reads.

---

> Read more:
> * [PermissionService (gRPC) — CheckPermission / CheckBulkPermissions](https://buf.build/authzed/api/file/main%3Aauthzed/api/v1/permission_service.proto)
> * [Consistency & ZedTokens](https://authzed.com/docs/spicedb/concepts/consistency)
> * [Caveats & context](https://authzed.com/docs/spicedb/concepts/caveats)
> * [Install SpiceDB with Docker](https://authzed.com/docs/spicedb/getting-started/install/docker)
