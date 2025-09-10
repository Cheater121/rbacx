# RBACX


[![CI](https://github.com/Cheater121/rbacx/actions/workflows/ci.yml/badge.svg)](https://github.com/Cheater121/rbacx/actions/workflows/ci.yml)
[![Docs](https://img.shields.io/badge/docs-website-blue)](https://cheater121.github.io/rbacx/)
![Coverage](./coverage.svg)

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

[![PyPI](https://img.shields.io/pypi/v/rbacx)](https://pypi.org/project/rbacx/)
[![Python](https://img.shields.io/pypi/pyversions/rbacx)](https://pypi.org/project/rbacx/)


Universal **RBAC/ABAC** policy engine for Python with a clean core, policy sets, a compact condition DSL (including time ops), and adapters for common web frameworks.

## Features
- Algorithms: `deny-overrides` (default), `permit-overrides`, `first-applicable`
- Conditions: `==`, `!=`, `<`, `<=`, `>`, `>=`, `contains`, `in`, `hasAll`, `hasAny`, `startsWith`, `endsWith`, `before`, `after`, `between`
- Explainability: `decision`, `reason`, `rule_id`/`last_rule_id`, `obligations`
- Policy sets: combine multiple policies with the same algorithms
- Hot reload: file/HTTP/S3 sources with ETag and a polling manager
- Types & lint: mypy-friendly core, Ruff-ready

## Installation
```bash
pip install rbacx
```

## Quickstart
```python
from rbacx.core.engine import Guard
from rbacx.core.model import Subject, Action, Resource, Context

policy = {
    "algorithm": "deny-overrides",
    "rules": [
        {
            "id": "doc_read",
            "effect": "permit",
            "actions": ["read"],
            "resource": {"type": "doc", "attrs": {"visibility": ["public", "internal"]}},
            "condition": {"hasAny": [ {"attr": "subject.roles"}, ["reader", "admin"] ]},
            "obligations": [{"mfa": True}]
        },
        {"id": "doc_deny_archived", "effect": "deny", "actions": ["*"], "resource": {"type": "doc", "attrs": {"archived": True}}},
    ],
}

g = Guard(policy)

d = g.evaluate_sync(
    subject=Subject(id="u1", roles=["reader"]),
    action=Action("read"),
    resource=Resource(type="doc", id="42", attrs={"visibility": "public"}),
    context=Context(attrs={"mfa": True}),
)

assert d.allowed is True
assert d.effect == "permit"
print(d.reason, d.rule_id)  # "matched", "doc_read"
```

### Decision schema
- `decision`: `"permit"` or `"deny"`
- `reason`: `"matched"`, `"explicit_deny"`, `"action_mismatch"`, `"resource_mismatch"`, `"condition_mismatch"`, `"condition_type_mismatch"`, `"no_match"`
- `rule_id` / `last_rule_id`
- `obligations`: list passed to the obligation checker

### Policy sets
```python
from rbacx.core.policyset import decide as decide_policyset

policyset = {"algorithm":"deny-overrides", "policies":[ policy, {"rules":[...]} ]}
result = decide_policyset(policyset, {"subject":..., "action":"read", "resource":...})
```

## Hot reloading
```python
from rbacx.core.engine import Guard
from rbacx.storage import FilePolicySource   # from rbacx.storage import HotReloader if you prefer
from rbacx.store.manager import PolicyManager

guard = Guard(policy={})
mgr = PolicyManager(guard, FilePolicySource("policy.json"))
mgr.poll_once()        # initial load
mgr.start_polling(10)  # background polling thread
```

## Packaging
- We ship `py.typed` so type checkers pick up annotations.
- Standard PyPA flow: `python -m build`, then `twine upload` to (Test)PyPI.

## License
MIT
