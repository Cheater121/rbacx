
# Policy authoring guide

This guide outlines how to write clear and maintainable RBAC/ABAC policies.

## Core concepts
- **RBAC** – users get **roles**, roles carry **permissions**. Keep roles stable, map users to roles dynamically.
- **ABAC** – decisions come from evaluating **attributes** of subject, resource, action, and environment against **rules**.
- **Combining algorithms** – `deny-overrides`, `permit-overrides`, `first-applicable`. Choose the one that matches your risk posture.

## Recommendations
- Start with **deny-by-default** (`deny-overrides`) and add explicit permits.
- Prefer **simple conditions**; avoid hidden coercions – types must match.
- Keep **resources typed** (e.g., `doc`, `invoice`) and avoid broad `*` unless required.
- Name every rule with unique **id** and tag high-risk rules with `obligations` (e.g., `mfa`).
- Validate policies with JSON Schema before loading.
- Document ownership and review cadence for policy files.

## Examples

### Permit with MFA requirement
```json
{
  "rules": [
    {
      "id": "doc_read",
      "effect": "permit",
      "actions": ["read"],
      "resource": { "type": "doc" },
      "obligations": [ { "type": "require_mfa" } ]
    }
  ]
}
```

### First-applicable
Stops on the first matched permit/deny, useful for ordered policies.

#### YAML example

```yaml
algorithm: first-applicable
rules:
  - id: p1
    effect: permit
    actions: [read]
    resource: { type: doc }
    condition:
      hasAny:
        - attr: subject.roles
        - [user, viewer]
  - id: d1
    effect: deny
    actions: [delete]
    resource: { type: doc }
```
