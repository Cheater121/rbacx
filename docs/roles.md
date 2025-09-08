
# Role hierarchy

Use `StaticRoleResolver` to expand roles with inheritance:

```python
from rbacx.core.roles import StaticRoleResolver
resolver = StaticRoleResolver({"admin":["manager"], "manager":["employee"]})
expanded = resolver.expand(["admin"])  # ['admin','employee','manager']
```

Wire into the `Guard`:

```python
guard = Guard(policy, role_resolver=resolver)
```

The RBAC standard (ANSI/INCITS 359-2004) includes role hierarchies.
