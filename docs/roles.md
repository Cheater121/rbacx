
# Role hierarchy

Use `StaticRoleResolver` to expand roles with inheritance:

```python
from rbacx.core.roles import StaticRoleResolver
resolver = StaticRoleResolver({"admin":["manager"], "manager":["employee"]})
expanded = resolver.expand(["admin"])  # ['admin','employee','manager']
```

Wire into the `Guard`:

```python
from rbacx import Guard

policy = {...}  # define yours here
resolver = ...  # use resolver from above

guard = Guard(policy, role_resolver=resolver)
```

The RBAC standard (ANSI/INCITS 359-2004) includes role hierarchies.

---

## Role shorthand in policies

For the common case of checking whether a subject holds one of a set of roles,
use the `roles` shorthand field on a rule instead of writing a `hasAny` condition:

```json
{
  "id": "admin-only",
  "effect": "permit",
  "actions": ["delete"],
  "resource": { "type": "doc" },
  "roles": ["admin", "superuser"]
}
```

This is equivalent to:

```json
{
  "id": "admin-only",
  "effect": "permit",
  "actions": ["delete"],
  "resource": { "type": "doc" },
  "condition": { "hasAny": [{ "attr": "subject.roles" }, ["admin", "superuser"]] }
}
```

When `StaticRoleResolver` is configured, `subject.roles` in the check already
contains the expanded set (e.g. `admin` → `[admin, manager, employee]`), so
the shorthand works correctly with role inheritance out of the box.
