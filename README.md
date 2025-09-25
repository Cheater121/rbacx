# RBACX


[![CI](https://github.com/Cheater121/rbacx/actions/workflows/ci.yml/badge.svg)](https://github.com/Cheater121/rbacx/actions/workflows/ci.yml)
[![Docs](https://img.shields.io/badge/docs-website-blue)](https://cheater121.github.io/rbacx/)
![Coverage](https://raw.githubusercontent.com/Cheater121/rbacx/badges/coverage.svg)


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
from rbacx import Action, Context, Guard, Subject, Resource

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
- `reason`: one of `"matched"`, `"explicit_deny"`, `"action_mismatch"`, `"condition_mismatch"`, `"condition_type_mismatch"`, `"resource_mismatch"`, `"no_match"`, `"obligation_failed"`
- `rule_id` and `last_rule_id` (both included for compatibility; `last_rule_id` is the matched rule id)
- `policy_id` (present for policy sets; `None` for single policies)
- `obligations`: list passed to the obligation checker (if a permit was gated)
- *(optional)* `challenge`: present when an authentication/step-up is required (e.g., for MFA); may be used to return `401` with the appropriate challenge header


### Policy sets
Default algorithm is:
```python
from rbacx.core.policyset import decide as decide_policyset

policyset = {"algorithm":"deny-overrides", "policies":[ policy, {"rules":[...]} ]}
result = decide_policyset(policyset, {"subject":..., "action":"read", "resource":...})
```
If you want to test, try this:
```python
from rbacx.core.policyset import decide as decide_policyset

# example set of policies
policyset = {
    "algorithm": "deny-overrides",
    "policies": [
        {"rules": [
            {"id": "allow_public_read", "effect": "permit", "actions": ["read"],
             "resource": {"type": "doc", "attrs": {"visibility": ["public"]}}}
        ]},
        {"rules": [
            {"id": "deny_archived", "effect": "deny", "actions": ["*"],
             "resource": {"type": "doc", "attrs": {"archived": True}}}
        ]},
    ],
}

# example request
req = {
    "subject": {"id": "u1", "roles": ["reader"]},
    "action": "read",
    "resource": {"type": "doc", "id": "42", "attrs": {"visibility": "public", "archived": False}},  # can try: would be `deny` if archived `True`
    "context": {},
}

res = decide_policyset(policyset, req)
print(res.get("effect", res))  # -> "permit"
```

## Hot reloading
Default algorithm is:
```python
from rbacx import Guard, HotReloader
from rbacx.store import FilePolicySource

guard = Guard(policy={})
mgr = HotReloader(guard, FilePolicySource("policy.json"), initial_load=...)
mgr.check_and_reload()        # initial load
mgr.start(10)  # background polling thread
```

If you want to test, try this:
```python
import json
import time
from rbacx import Action, Context, Guard, HotReloader, Resource, Subject
from rbacx.store import FilePolicySource

# create a tiny policy file next to the script
policy_path = "policy.json"
json.dump({
    "algorithm": "deny-overrides",
    "rules": [{
        "id": "allow_public_read", "effect": "permit", "actions": ["read"],
        "resource": {"type": "doc", "attrs": {"visibility": ["public"]}}
    }]
}, open(policy_path, "w", encoding="utf-8"))

guard = Guard({})
mgr = HotReloader(guard, FilePolicySource(policy_path), initial_load=True)
mgr.check_and_reload()  # initial load

print(guard.evaluate_sync(
    subject=Subject(id="u1", roles=["reader"]),
    action=Action("read"),
    resource=Resource(type="doc", id="1", attrs={"visibility": "public"}),
    context=Context(),
).effect)  # -> "permit"

# update policy and wait 3 second for reload
json.dump({
    "algorithm": "deny-overrides",
    "rules": [{"id": "deny_all", "effect": "deny", "actions": ["*"], "resource": {"type": "doc"}}]
}, open(policy_path, "w", encoding="utf-8"))
mgr.start(3)  # starting polling
time.sleep(3)

print(guard.evaluate_sync(
    subject=Subject(id="u1", roles=["reader"]),
    action=Action("read"),
    resource=Resource(type="doc", id="1", attrs={"visibility": "public"}),
    context=Context(),
).effect)  # -> "deny"
```

## Quick links
- 📌 [Deprecation Policy](DEPRECATION.md)
- 🛡️ [API Stability Guarantees](API_STABILITY.md)
- 🔐 [Security Policy](SECURITY.md)
- 🤝 [Code of Conduct](CODE_OF_CONDUCT.md)

## Packaging
- We ship `py.typed` so type checkers pick up annotations.
- Standard PyPA flow: `python -m build`, then `twine upload` to (Test)PyPI.

## License
MIT
