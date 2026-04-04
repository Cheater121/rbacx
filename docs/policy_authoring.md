# Policy authoring guide

This guide outlines how to write clear and maintainable RBAC/ABAC/ReBAC policies.

## Core concepts

* **RBAC** – users get **roles**, roles carry **permissions**. Keep roles stable, map users to roles dynamically.
* **ABAC** – decisions come from evaluating **attributes** of subject, resource, action, and environment against **rules**.
* **ReBAC** – decisions can depend on **relationships** between a subject and a resource (e.g., *user —owner→ document*). Relationships are typically managed in a graph/tuple store and checked via a `RelationshipChecker` port. See *Relationship conditions* below for policy syntax.
* **Combining algorithms** – `deny-overrides`, `permit-overrides`, `first-applicable`. Choose the one that matches your risk posture.
* **Role shorthand** – `"roles": ["admin", "editor"]` is sugar for a `hasAny` check on `subject.roles`; see below.

## Recommendations

* Start with **deny-by-default** (`deny-overrides`) and add explicit permits.
* Prefer **simple conditions**; avoid hidden coercions – types must match.
* Keep **resources typed** (e.g., `doc`, `invoice`) and avoid broad `*` unless required.
* Name every rule with unique **id** and tag high-risk rules with `obligations` (e.g., `mfa`).
* Validate policies with JSON Schema before loading and lint them in CI.
* Document ownership and review cadence for policy files.
* If strict mode is enabled, avoid relying on implicit coercions in `resource.id`, `resource.type`, `resource.attrs`, and pass aware `datetime` to time conditions. See [Types](types.md).
* For ReBAC, **model relationships narrowly** (least privilege), prefer **direct relations** over deep traversals, and document how relationship data is produced and expired.

## Policy structure (JSON/YAML)

Common top-level keys:

* `algorithm` — combining algorithm (optional; default `deny-overrides`).
* `rules` — list of rule objects.
* Each rule can include:
  `id`, `effect` (`permit`/`deny`), `actions`, `resource` (with `type`, optional `ids`/`attrs`), optional `subject` matchers, `condition`, `obligations`.

## Conditions

Built-in operators include:

* **Comparisons**: `==`, `!=`, `<`, `<=`, `>`, `>=`
* **Collections**: `hasAny`, `hasAll`, `in`, `contains`
* **Time**: `before`, `after`, `between`

### Relationship conditions (ReBAC)

Use `rel` to require that a subject has a specific **relation** to the resource. The engine consults the configured `RelationshipChecker`.

**Short form** (uses the request’s subject/resource):

```json
{ "rel": "owner" }
```

**Extended form**:

```json
{
  "rel": {
    "relation": "editor",
    "subject": { "type": "user", "id": "u123" },   // optional override
    "resource": { "type": "doc", "id": "d42" },    // optional override
    "ctx": { "reason": "delegation" }              // optional per-check context
  }
}
```

Semantics:

* If `subject`/`resource` are omitted, the engine uses the inputs of the access check.
* `ctx` (if provided) is merged into a dedicated ReBAC context for the checker.
* **Fail-closed**: if no `RelationshipChecker` is configured, `rel` evaluates to `false`.
* Combine with ABAC/RBAC conditions as usual (e.g., require a role **and** a relationship).

> Tip: In tuple/graph systems (e.g., SpiceDB, OpenFGA), relationships are expressed as *subject–relation–object* and can be modeled for users, groups, and object hierarchies.

## Role shorthand

Instead of writing a `hasAny` condition for the common case of checking
`subject.roles`, use the `roles` shorthand directly on the rule:

```json
{
  "id": "doc-read",
  "effect": "permit",
  "actions": ["read"],
  "resource": { "type": "doc" },
  "roles": ["admin", "editor"]
}
```

This is exactly equivalent to:

```json
{
  "id": "doc-read",
  "effect": "permit",
  "actions": ["read"],
  "resource": { "type": "doc" },
  "condition": { "hasAny": [{ "attr": "subject.roles" }, ["admin", "editor"]] }
}
```

### Combining `roles` with `condition`

When both `roles` and `condition` are present the engine combines them with
**AND** — both must be satisfied for the rule to match:

```json
{
  "id": "doc-read-sensitive",
  "effect": "permit",
  "actions": ["read"],
  "resource": { "type": "doc" },
  "roles": ["admin"],
  "condition": { "==": [{ "attr": "resource.attrs.sensitivity" }, "high"] }
}
```

### Conflict: both `roles` and `condition` constrain `subject.roles`

If `condition` also references `subject.roles` the engine still combines with
AND — the result is the **intersection** and may be narrower than intended:

```json
{
  "roles": ["admin"],
  "condition": { "hasAny": [{ "attr": "subject.roles" }, ["admin", "user"]] }
}
```

Effective check: `subject.roles ∩ [admin]` AND `subject.roles ∩ [admin, user]`
→ only `admin` passes (the wider condition is shadowed by the narrower `roles`).

> **Recommendation:** avoid redundant role constraints. Run `rbacx lint` before
> deploying — the linter emits `ROLES_CONDITION_OVERLAP` when it detects this
> pattern and explains the AND semantics in the warning message.

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

### ReBAC: owner may edit their document

```json
{
  "rules": [
    {
      "id": "doc_edit_owner",
      "effect": "permit",
      "actions": ["edit"],
      "resource": { "type": "doc" },
      "condition": { "rel": "owner" }
    }
  ]
}
```

### Combine ABAC and ReBAC: editors in same tenant, during a time window

```yaml
algorithm: deny-overrides
rules:
  - id: doc_edit_editor_tenant_hours
    effect: permit
    actions: [edit]
    resource: { type: doc, attrs: { tenant_id: "${context.tenant_id}" } }
    condition:
      and:
        - rel: editor
        - between:
            - attr: context.now
            - ["2025-01-01T09:00:00Z", "2025-12-31T18:00:00Z"]
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
    roles: [user, viewer]          # shorthand for hasAny on subject.roles
    # equivalent (legacy syntax):
    # condition:
    #   hasAny:
    #     - attr: subject.roles
    #     - [user, viewer]
  - id: d1
    effect: deny
    actions: [delete]
    resource: { type: doc }
```

## Testing & validation tips

* Write **table-driven tests** per rule (inputs → expected decision).
* Include **negative tests** for missing relations (ReBAC) and type mismatches (ABAC).
* In CI, run the **linter** and **schema validation** before deploying policies.
* For ReBAC backends, seed **fixture tuples/relationships** for deterministic tests.

> **Depth limit:** condition trees are evaluated up to `MAX_CONDITION_DEPTH`
> levels of `and`/`or`/`not` nesting (default: 50).  Real policies are
> well within this limit; it exists solely as a DoS guard for policies
> loaded from external sources.
