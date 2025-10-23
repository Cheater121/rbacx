# Local ReBAC (built-in)

The local ReBAC provider ships with RBACX, requires no extra dependencies, and is ideal for tests, demos, and small apps.

It evaluates **relationship tuples** of the form:

```
subject --relation--> resource
```

where both `subject` and `resource` are string refs like `"type:id"` (e.g., `"user:alice"`, `"document:doc1"`). If `":"` is omitted, the default type is `"user"`.

---

## Userset primitives

Local userset-rewrite rules are built from these primitives (they can be nested in lists to mean “union”):

* `This()` — direct relation on the same object (subject has `relation` to the *current* resource).
* `ComputedUserset("relation")` — evaluate another relation **on the same object**.
* `TupleToUserset("tupleset", "computed_userset")` — follow an **object→object** edge from the current resource via `tupleset`, then evaluate `computed_userset` on the **target** object.

Type alias used in the API:

```python
UsersetExpr = This | ComputedUserset | TupleToUserset | list["UsersetExpr"]
```

---

## Building tuples and rules

```python
from rbacx.rebac.local import (
    InMemoryRelationshipStore,
    LocalRelationshipChecker,
    This, ComputedUserset, TupleToUserset, UsersetExpr
)

# 1) Relationship tuples (facts)
store = InMemoryRelationshipStore()

# Direct user→document relation
store.add("user:alice", "owner", "document:doc1")

# Object→object edges (the 'subject' holds the TARGET object)
# folder:f1 --parent--> document:doc1  (doc1 is inside folder f1)
store.add("folder:f1", "parent", "document:doc1")

# Group grants: document:doc1 --granted--> group:g1 (expressed as group:g1 'granted' document:doc1)
store.add("group:g1", "granted", "document:doc1")
# User membership in that group
store.add("user:alice", "member", "group:g1")

# 2) Userset rewrite rules per object type
rules: dict[str, dict[str, UsersetExpr]] = {
    "document": {
        # viewer is granted directly, or via owner, parent.folder.viewer, or group grants
        "viewer": [
            This(),
            ComputedUserset("owner"),
            TupleToUserset("parent", "viewer"),
            TupleToUserset("granted", "member"),
        ],
        "owner": [This()],
        # optional:
        "editor": [This(), ComputedUserset("owner")],
    },
    "folder": {
        "viewer": [This()],
    },
    "group": {
        "member": [This()],
    },
}

checker = LocalRelationshipChecker(
    store,
    rules=rules,
    # optional: caveat predicates registry, see below
    caveat_registry=None,
    # safety limits (defaults shown)
    max_depth=8,
    max_nodes=10_000,
    deadline_ms=50,
)
```

> Tip: for common “viewer/editor/owner (+parent, +group grants)” patterns, see `rbacx.rebac.helpers.standard_userset(parent_rel=..., with_group_grants=True)`.

---

## Using `rel` in policy

Require that the request’s **subject** holds a given relation to the **resource**:

```json
{
  "algorithm": "deny-overrides",
  "rules": [
    {
      "id": "doc-read-if-viewer",
      "effect": "permit",
      "actions": ["read"],
      "resource": { "type": "document" },
      "condition": { "rel": "viewer" }
    }
  ]
}
```

Extended form (override subject/resource, pass per-check context merged into `context._rebac`):

```json
{
  "condition": {
    "rel": {
      "relation": "viewer",
      "subject": "user:alice",
      "resource": "document:doc1",
      "ctx": { "reason": "delegation" }
    }
  }
}
```

Wire it up:

```python
from rbacx import Guard  # or: from rbacx.core.engine import Guard

guard = Guard(policy, relationship_checker=checker)
```

See runnable examples in:

* `examples/rebac/rebac_local_demo.py`
* `examples/rebac/rebac_local_demo_with_helper.py`
* `examples/rebac/rebac_more_realistic_demo.py`

---

## Safety limits & caveats

`LocalRelationshipChecker` enforces soft limits to protect against pathological graphs:

* `max_depth`: maximum rewrite recursion depth
* `max_nodes`: maximum visited nodes
* `deadline_ms`: time budget per check

### Conditional tuples (caveats)

You can mark a tuple with a **caveat name** and provide a predicate via `caveat_registry`. The predicate receives the merged ReBAC context (`context._rebac` + `ctx` from the `rel` condition) and must return truthy/falsey.

```python
def is_business_hours(ctx: dict | None) -> bool:
    # your logic here (ctx may be None)
    return bool(ctx and ctx.get("hour", 0) in range(9, 18))

checker = LocalRelationshipChecker(
    store,
    rules=rules,
    caveat_registry={"business_hours": is_business_hours},
)

# Attach a caveat to a direct relation:
store.add("user:alice", "viewer", "document:doc1", caveat="business_hours")
```

In policy, pass `ctx` if needed:

```json
{ "rel": { "relation": "viewer", "ctx": { "hour": 10 } } }
```

Unknown caveats or exceptions inside predicates are treated as **False** (fail-closed).

---

## Batch checks

```python
# Evaluates sequentially with a small per-call memo to avoid duplicate work.
results: list[bool] = checker.batch_check(
    [("user:alice", "viewer", "document:doc1"),
     ("user:alice", "owner",  "document:doc1")]
)
```

---

## Constructor (reference)

```python
LocalRelationshipChecker(
    store: InMemoryRelationshipStore,
    *,
    # rules[object_type][relation] -> UsersetExpr
    rules: dict[str, dict[str, UsersetExpr]] | None = None,
    caveat_registry: dict[str, Callable[[dict[str, Any] | None], bool]] | None = None,
    max_depth: int = 8,
    max_nodes: int = 10_000,
    deadline_ms: int = 50,
)
```

* `InMemoryRelationshipStore.add(subject, relation, resource, caveat=None)` stores a tuple (optionally conditional).
* Direct relations are checked first; userset rewrites (`This`, `ComputedUserset`, `TupleToUserset`) expand the search **breadth-first** until a match is found or limits are hit.
* Timeouts/limits result in a **False** decision for that check.
