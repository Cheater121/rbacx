# OpenFGA Provider

Install: `pip install "rbacx[rebac-openfga]"`

```python
from rbacx.rebac.openfga import OpenFGAChecker, OpenFGAConfig

cfg = OpenFGAConfig(
    api_url="http://localhost:8080",     # e.g., https://api.fga.example
    store_id="01H...",                   # your Store ID
    authorization_model_id=None,         # optional: can be set here or per-check
    api_token=None,                      # optional: adds Authorization: Bearer <token>
)

checker = OpenFGAChecker(cfg)  # sync and async (httpx) are supported
```

* Uses REST endpoints **`POST /stores/{store_id}/check`** and **`POST /stores/{store_id}/batch-check`**; decisions read the `allowed` boolean from the response. ([openfga.dev][1])
* The server-side **Batch Check** returns a **`results` array** of objects each carrying a `correlationId` and `allowed`; ordering is **not guaranteed**, use `correlationId` to pair responses to requests. Requires OpenFGA **server ≥ 1.8.0**. ([openfga.dev][2])

See `deploy/compose/openfga/` for a local Docker Compose and `deploy/compose/openfga/demo_openfga.py`.

---

## Configuration notes

* `authorization_model_id` (optional) can be set globally in `OpenFGAConfig` or overridden per request.
* `api_token` adds the `Authorization: Bearer <token>` header when your OpenFGA instance requires auth.
* The checker forwards **`context`** from RBACX to OpenFGA so **Conditions** (conditional relationship tuples) can evaluate it during checks.

---

## Batch Check

When checking many (user, relation, object) tuples:

```python
pairs = [
    ("user:alice", "viewer", "document:doc1", "1"),
    ("user:alice", "editor", "document:doc1", "2"),
    ("user:alice", "owner",  "document:doc1", "3"),
]
result = checker.batch_check(pairs)
# result["results"] -> list of {"correlationId": "...", "allowed": bool, "request": {...}}
```

The provider sets a `correlationId` per input; the server responds with a `results` **array** (not a map).

---
> Read more:
> * [Concepts](https://openfga.dev/docs/concepts)
> * [Relationship Queries: Check, Read, Expand, and ListObjects](https://openfga.dev/docs/interacting/relationship-queries)
> * [Conditions](https://openfga.dev/docs/modeling/conditions)
