# Adapters — build your own in 3 steps

Adapters are thin wrappers around the RBACX `Guard`. They map a framework event/request to a decision and translate that decision into the framework’s native outcome. Because the core is framework-independent, you can integrate it into web apps, GUIs, CLIs, services — anywhere.

**Terminology (S/A/R/C)**

* **Subject** — who acts (user id, roles, attributes)
* **Action** — what operation is requested (string key, e.g. `"document.update"`)
* **Resource** — what it targets (domain object type/id/attributes)
* **Context** — extra facts (tenant, flags, mode, time, environment, etc.)

---

## What you need before you start

* A place to read **who** acts (auth/session), **what** is requested (command/router), **what** it targets (current domain entity), and **context** (tenant/flags/mode/time/etc.).
* A `Guard` instance available where you handle requests/commands.
* A native way to express **deny** in your environment (return code/exception/HTTP 403/etc.).

**Guard initialization (policy, logging, metrics, roles, obligations)**

```python
from rbacx import Guard

guard = Guard(
    policy=...,                  # required: policy or policy set (as a dict)
    logger_sink=...,             # optional: object with .log(payload) -> None/awaitable
    metrics=...,                 # optional: object with .inc(name, labels) and/or .observe(name, value, labels)
    obligation_checker=...,      # optional: validates obligations (defaults to BasicObligationChecker)
    role_resolver=...,           # optional: expands roles (may be sync or async)
)
```

> Notes:
>
> * `Guard` has a single async core; `evaluate_sync` wraps it safely (runs directly if no loop is active, or uses a helper thread if a loop is already running).

---

## Choose sync vs async

* Use **`guard.evaluate_sync(...)`** in synchronous handlers.
* Use **`await guard.evaluate_async(...)`** when your app runs an event loop (evented GUIs, async servers).

Rule of thumb: if your handler is already `async` or runs on an event loop, use the async call; otherwise use the sync call.

---

## The 3 steps to implement your adapter

1. **Build the environment** — convert your event/request to `(Subject, Action, Resource, Context)` with an `EnvBuilder`.
2. **Evaluate** — call the appropriate `Guard` method (sync or async).
3. **Translate the result** — on *permit* continue; on *deny* return the native “forbidden” outcome for your framework.

---

## Walkthrough (GUI example)

This example shows a realistic desktop wiring: commands arrive via your controller, the current target comes from a selection model, and app-level facts come from a context snapshot. The same 1–2–3 applies to web or any other stack.

### 1) Build the environment (S/A/R/C)

```python
from typing import Any, Tuple
from rbacx import Subject, Action, Resource, Context

class AuthService:        # who acts
    @property
    def current_user(self): ...  # -> object with .id, .roles, .attrs

class CommandRegistry:    # what operation
    def to_action_name(self, command_id: str) -> str: ...

class SelectionBridge:    # what it targets (current domain entity)
    def current_resource(self) -> tuple[str, str, dict]:
        # e.g., ("document", "DOC-123", {"owner": "u17"})
        ...

class AppContext:         # extra facts
    def snapshot(self) -> dict: ...

class RbacEnv:
    def __init__(self, auth: AuthService, commands: CommandRegistry,
                 selection: SelectionBridge, appctx: AppContext):
        self.auth, self.commands, self.selection, self.appctx = auth, commands, selection, appctx

    def build_env(self, raw_event: Any) -> Tuple[Subject, Action, Resource, Context]:
        # Subject
        u = self.auth.current_user
        subject = Subject(id=u.id, roles=list(u.roles), attrs=dict(u.attrs or {}))

        # Action
        command_id = getattr(raw_event, "command_id", None) or str(raw_event)
        action = Action(name=self.commands.to_action_name(command_id))

        # Resource
        r_type, r_id, r_attrs = self.selection.current_resource()
        resource = Resource(type=r_type, id=r_id, attrs=r_attrs)

        # Context
        context = Context(attrs=self.appctx.snapshot())

        # Edge cases (no selection / no command)
        if r_type is None or r_id is None:
            resource = Resource(type="*", id=None, attrs={})
        if not action.name:
            action = Action(name="unknown")

        return subject, action, resource, context
```

### 2) Evaluate

```python
env = RbacEnv(auth, commands, selection, appctx)

def handle_command(event):
    s, a, r, c = env.build_env(event)
    return guard.evaluate_sync(s, a, r, c)

# async variant (if your GUI runs an event loop integrated with asyncio)
async def handle_command_async(event):
    s, a, r, c = env.build_env(event)
    return await guard.evaluate_async(s, a, r, c)
```

### 3) Translate the result

```python
def apply_decision(decision):
    if decision.allowed:
        return {"ok": True}
    # keep diagnostics off by default; enable explicitly if needed
    return {"ok": False, "error": "Forbidden"}
```

### End-to-end snippet (copy & paste)

```python
# 1) build
s, a, r, c = env.build_env(event)
# 2) evaluate
decision = guard.evaluate_sync(s, a, r, c)
# 3) translate
result = {"ok": True} if decision.allowed else {"ok": False, "error": "Forbidden"}
```

---

## Decision shape (what you can use)

`Decision` exposes: `allowed`, `effect`, `reason`, `rule_id`, `policy_id`, `obligations`, `challenge`. Keep reasons/ids disabled by default; surface them only in explicit diagnostic/audit modes.

---

## Practical tips

* **Centralize S/A/R/C.** Keep one `EnvBuilder` responsible for turning events into `(Subject, Action, Resource, Context)`.
* **Match your runtime.** Choose sync or async once and keep handlers consistent.
* **Safe by default.** Don’t surface `reason`/`rule_id`/`policy_id` unless explicitly enabled.
* **Guard construction.** Start minimal (`policy` only); add `logger_sink`, `metrics`, `role_resolver`, or a custom `obligation_checker` as your application needs grow.

---

## Takeaways

* Adapters are thin wrappers: **build → evaluate → translate**.
* The engine is platform-neutral: the same contract works for GUI, web, CLI, and services.
* With a clear `EnvBuilder` and the right sync/async call, integrating RBACX is straightforward.
