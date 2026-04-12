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

## Decision object

Fields returned by all `Guard.evaluate*` methods:

| Field | Type | Description |
|---|---|---|
| `allowed` | `bool` | Whether access is granted |
| `effect` | `str` | Declared effect: `"permit"` or `"deny"` |
| `obligations` | `List[Dict]` | Obligations from the matched rule |
| `challenge` | `str \| None` | Machine-readable auth challenge (e.g. `"mfa"`) |
| `rule_id` | `str \| None` | ID of the matched rule |
| `policy_id` | `str \| None` | ID of the matched policy (policy sets only) |
| `reason` | `str \| None` | Why the decision was made — see [Reasons](reasons.md) |
| `trace` | `List[RuleTrace] \| None` | Per-rule evaluation log; `None` unless `explain=True` |

---

## Decision trace (`explain=True`)

Pass `explain=True` to any evaluation method to get a per-rule evaluation log:

```python
d = guard.evaluate_sync(subject, action, resource, context, explain=True)

for entry in d.trace:
    status = "matched" if entry.matched else f"skipped ({entry.skip_reason})"
    print(f"  rule {entry.rule_id!r} [{entry.effect}] → {status}")
```

When `explain=False` (default) `Decision.trace` is `None` — zero overhead on the hot path.

`explain=True` is supported on all four evaluation methods:

```python
d         = guard.evaluate_sync(..., explain=True)
d         = await guard.evaluate_async(..., explain=True)
decisions = guard.evaluate_batch_sync([...], explain=True)
decisions = await guard.evaluate_batch_async([...], explain=True)
```

**`RuleTrace` fields**

| Field | Type | Description |
|---|---|---|
| `rule_id` | `str` | Rule `id` as declared in the policy |
| `effect` | `str` | `"permit"` or `"deny"` |
| `matched` | `bool` | `True` when the rule fully matched |
| `skip_reason` | `str \| None` | Why the rule was skipped; `None` when `matched=True` |

Possible `skip_reason` values: `"action_mismatch"`, `"resource_mismatch"`,
`"condition_mismatch"`, `"condition_type_mismatch"`, `"condition_depth_exceeded"`.

```python
from rbacx import RuleTrace  # importable from root package
```

---

## Batch evaluation

Evaluate multiple access requests in one call — useful for UI state checks
(which buttons/actions to show for a given user).

```python
decisions = await guard.evaluate_batch_async([
    (subject, Action("read"),   resource, ctx),
    (subject, Action("write"),  resource, ctx),
    (subject, Action("delete"), resource, ctx),
], timeout=2.0)

decisions = guard.evaluate_batch_sync([...])
```

**Signatures**

```python
async def evaluate_batch_async(
    requests: Sequence[tuple[Subject, Action, Resource, Context | None]],
    *,
    explain: bool = False,
    timeout: float | None = None,
) -> list[Decision]: ...

def evaluate_batch_sync(
    requests: Sequence[tuple[Subject, Action, Resource, Context | None]],
    *,
    explain: bool = False,
    timeout: float | None = None,
) -> list[Decision]: ...
```

**Guarantees**

* Results are in the **same order** as the input.
* Requests run **concurrently** via `asyncio.gather` — total time equals the slowest check.
* Empty input returns `[]` immediately.
* `timeout` bounds total wall-clock time; raises `asyncio.TimeoutError` on expiry.
* All DI hooks (metrics, logger, cache, obligations, handlers) apply per request.

---

## Executable obligation handlers

Register handlers that `Guard` calls automatically after a `permit` decision:

```python
from rbacx.core.engine import ObligationNotMetError

def check_mfa(decision, context):
    if not context.attrs.get("mfa"):
        raise ObligationNotMetError("MFA required", challenge="mfa")

guard.register_obligation_handler("require_mfa", check_mfa)
```

**Signature**

```python
guard.register_obligation_handler(obligation_type: str, handler: Callable) -> None
```

Handler signature: `(decision: Decision, context: Context) -> None` — sync or async.

`ObligationNotMetError(message="", *, challenge=None)` — flips the decision to
`deny` with `reason="obligation_failed"`.  `challenge` is propagated to
`Decision.challenge`.  Any other exception also causes deny (fail-closed).

See [Obligations](obligations.md) for full details and behaviour.

---

## `require_batch_access` (FastAPI)

FastAPI dependency that evaluates multiple `(action, resource_type)` pairs in
one batch call and returns `list[Decision]`:

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
