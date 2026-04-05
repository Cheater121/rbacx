# API Reference

::: rbacx.core.engine

---

::: rbacx.core.model

---

::: rbacx.core.policy

---

::: rbacx.core.policyset

---

::: rbacx.core.ports

---

::: rbacx.core.relctx

---

::: rbacx.logging.decision_logger

---

::: rbacx.logging.context

---

::: rbacx.core.obligations

---

::: rbacx.core.cache

---

::: rbacx.core.roles

---

::: rbacx.policy

---

::: rbacx.rebac

---

::: rbacx.rebac.helpers

---

::: rbacx.rebac.openfga

---

::: rbacx.rebac.spicedb

---

::: rbacx.store.file_store

---

::: rbacx.store.s3_store

---

::: rbacx.store.http_store

---

::: rbacx.adapters.asgi

---

::: rbacx.adapters.asgi_logging

---

::: rbacx.adapters.asgi_accesslog

---

::: rbacx.adapters.flask

---

::: rbacx.adapters.django.middleware

---

::: rbacx.adapters.django.trace

---

::: rbacx.adapters.litestar

---

## Decision explanation / trace

Pass `explain=True` to any evaluation method to get a per-rule evaluation log
attached to the returned `Decision`.

```python
d = guard.evaluate_sync(subject, action, resource, context, explain=True)

for entry in d.trace:
    status = "matched" if entry.matched else f"skipped ({entry.skip_reason})"
    print(f"  rule {entry.rule_id!r} [{entry.effect}] → {status}")
```

When `explain=False` (the default) `Decision.trace` is `None` — there is no
overhead on the hot path.

**`RuleTrace` fields**

| Field | Type | Description |
|---|---|---|
| `rule_id` | `str` | The `id` field of the rule as declared in the policy |
| `effect` | `str` | Declared effect: `"permit"` or `"deny"` |
| `matched` | `bool` | `True` when the rule fully matched; `False` when skipped |
| `skip_reason` | `str \| None` | Why the rule was skipped, or `None` when `matched=True` |

Possible `skip_reason` values: `"action_mismatch"`, `"resource_mismatch"`,
`"condition_mismatch"`, `"condition_type_mismatch"`, `"condition_depth_exceeded"`.

**Algorithm-specific trace behaviour**

* `deny-overrides` — trace includes every rule up to and including the first
  matching deny (the loop breaks there).  When only permits fire, all rules
  are present.
* `permit-overrides` — trace up to and including the first matching permit.
* `first-applicable` — trace up to and including the first match; subsequent
  rules are absent.
* No match — every rule appears in the trace with `matched=False`.

`explain=True` is supported on all four evaluation methods:

```python
# Single request
d = guard.evaluate_sync(..., explain=True)
d = await guard.evaluate_async(..., explain=True)

# Batch — explain applies to every request in the batch
decisions = guard.evaluate_batch_sync([...], explain=True)
decisions = await guard.evaluate_batch_async([...], explain=True)
```

`RuleTrace` is importable directly from the root package:

```python
from rbacx import RuleTrace
```

---

## Batch evaluation

`Guard` exposes two methods for evaluating multiple access requests in a single
call — useful for populating UIs that need to know which buttons/tabs/actions
to show for a given user.

```python
from rbacx import Guard, Subject, Action, Resource, Context

guard = Guard(policy)
subject = Subject(id="u1", roles=["editor"])
resource = Resource(type="document", id="doc-42")
ctx = Context(attrs={"mfa": True})

# Async (preferred in ASGI applications)
decisions = await guard.evaluate_batch_async([
    (subject, Action("read"),   resource, ctx),
    (subject, Action("write"),  resource, ctx),
    (subject, Action("delete"), resource, ctx),
])

# Sync (works everywhere, including inside a running event loop)
decisions = guard.evaluate_batch_sync([
    (subject, Action("read"),   resource, ctx),
    (subject, Action("write"),  resource, ctx),
    (subject, Action("delete"), resource, ctx),
])

for action_name, decision in zip(["read", "write", "delete"], decisions):
    print(action_name, "→", "allow" if decision.allowed else "deny")
```

**Signature**

```python
async def evaluate_batch_async(
    self,
    requests: Sequence[tuple[Subject, Action, Resource, Context | None]],
    *,
    explain: bool = False,
    timeout: float | None = None,
) -> list[Decision]: ...

def evaluate_batch_sync(
    self,
    requests: Sequence[tuple[Subject, Action, Resource, Context | None]],
    *,
    explain: bool = False,
    timeout: float | None = None,
) -> list[Decision]: ...
```

**Guarantees**

* Results are returned in the **same order** as the input sequence.
* Requests are evaluated **concurrently** via `asyncio.gather` — wall-clock
  time grows with the slowest single request rather than the total count.
* An **empty** input list returns `[]` immediately without any evaluation.
* `timeout` (seconds) bounds the total wall-clock time for the batch.
  `asyncio.TimeoutError` is raised if the deadline is exceeded.  ``None``
  (default) means no deadline.
* `Context` may be `None` for any individual request.
* All DI hooks (metrics, logger, obligation checker, role resolver, cache) are
  invoked **per request**, exactly as with `evaluate_async` / `evaluate_sync`.
* If any individual request raises an exception the entire batch propagates
  that exception (**fail-fast** semantics, consistent with `asyncio.gather`).

---

## Decision object

Fields returned by `Guard.evaluate*`:

* `allowed: bool`
* `effect: "permit" | "deny"`
* `obligations: List[Dict[str, Any]]`
* `challenge: Optional[str]`
* `rule_id: Optional[str]`
* `policy_id: Optional[str]`
* `reason: Optional[str]`
* `trace: Optional[List[RuleTrace]]` — populated when `explain=True`; `None` by default

---

## `require_batch_access` (FastAPI)

FastAPI dependency that evaluates multiple `(action, resource_type)` pairs in
one `evaluate_batch_async` call and returns a `list[Decision]`.

```python
from rbacx.adapters.fastapi import require_batch_access
from rbacx import Subject

def build_subject(request: Request) -> Subject:
    return Subject(id="user", roles=[request.headers.get("X-Role", "viewer")])

@app.get("/ui-state")
async def ui_state(
    decisions=Depends(
        require_batch_access(
            guard,
            [("read", "document"), ("write", "document"), ("delete", "document")],
            build_subject,
            timeout=2.0,
        )
    )
):
    return {
        "can_read":   decisions[0].allowed,
        "can_write":  decisions[1].allowed,
        "can_delete": decisions[2].allowed,
    }
```

---

## AI Policy Authoring

::: rbacx.ai

---

### YAML policies

All built-in policy sources accept JSON and, with the optional `rbacx[yaml]` extra, YAML.

* File: detected by extension `.yaml` / `.yml`.
* HTTP: detected by `Content-Type` (e.g., `application/yaml`, `application/x-yaml`, `text/yaml`) or URL suffix.
* S3: detected by key suffix `.yaml` / `.yml`.

> Internally YAML is parsed and validated against the same JSON Schema as JSON.
