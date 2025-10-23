# Policy authoring guide

This guide outlines how to write clear and maintainable RBAC/ABAC/ReBAC policies.

## Core concepts

* **RBAC** – users get **roles**, roles carry **permissions**. Keep roles stable, map users to roles dynamically.
* **ABAC** – decisions come from evaluating **attributes** of subject, resource, action, and environment against **rules**.
* **ReBAC** – decisions can depend on **relationships** between a subject and a resource (e.g., *user —owner→ document*). Relationships are typically managed in a graph/tuple store and checked via a `RelationshipChecker` port. See *Relationship conditions* below for policy syntax. ([AuthZed][1])
* **Combining algorithms** – `deny-overrides`, `permit-overrides`, `first-applicable`. Choose the one that matches your risk posture.

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

### Combine ABAC and ReBAC: editors in same tenant, during office hours

```yaml
algorithm: deny-overrides
rules:
  - id: doc_edit_editor_tenant_hours
    effect: permit
    actions: [edit]
    resource: { type: doc, attrs: { tenant_id: "${context.tenant_id}" } }
    condition:
      all:
        - rel: editor
        - between:
            attr: context.now
            start: "09:00"
            end: "18:00"
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

## Testing & validation tips

* Write **table-driven tests** per rule (inputs → expected decision).
* Include **negative tests** for missing relations (ReBAC) and type mismatches (ABAC).
* In CI, run the **linter** and **schema validation** before deploying policies.
* For ReBAC backends, seed **fixture tuples/relationships** for deterministic tests.
