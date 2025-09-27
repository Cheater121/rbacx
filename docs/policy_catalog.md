
# Policy Catalog (RBAC & ABAC patterns)

## Tenant isolation (resource.owner/tenant)
```json
{
  "algorithm": "deny-overrides",
  "rules": [
    {
      "id": "tenant_read",
      "effect": "permit",
      "actions": ["read"],
      "resource": { "type": "doc" },
      "condition": { "==": [ { "attr": "subject.tenant" }, { "attr": "resource.tenant" } ] }
    },
    {
      "id": "tenant_write",
      "effect": "permit",
      "actions": ["write"],
      "resource": { "type": "doc" },
      "condition": { "==": [ { "attr": "subject.tenant" }, { "attr": "resource.tenant" } ] }
    }
  ]
}
```

## Owner-only
```json
{
  "algorithm": "deny-overrides",
  "rules": [
    {
      "id": "owner",
      "effect": "permit",
      "actions": ["*"],
      "resource": { "type": "doc" },
      "condition": { "==": [ { "attr": "subject.id" }, { "attr": "resource.owner" } ] }
    }
  ]
}
```

## Clearance >= classification (numbers)
```json
{
  "algorithm": "deny-overrides",
  "rules": [
    {
      "id": "clearance",
      "effect": "permit",
      "actions": ["read"],
      "resource": { "type": "record" },
      "condition": { ">=": [ { "attr": "subject.clearance" }, { "attr": "resource.classification" } ] }
    }
  ]
}
```

## Time window (business hours) + MFA obligation
```json
{
  "algorithm": "permit-overrides",
  "rules": [
    {
      "id": "work_hours",
      "effect": "permit",
      "actions": ["read"],
      "resource": { "type": "doc" },
      "condition": { "and": [
        { ">=": [ { "attr": "context.hour" }, 8 ] },
        { "<":  [ { "attr": "context.hour" }, 18 ] }
      ] }
    },
    {
      "id": "mfa",
      "effect": "permit",
      "actions": ["read"],
      "resource": { "type": "doc" },
      "condition": { "==": [ { "attr": "context.mfa" }, true ] },
      "obligations": [ { "type": "require_mfa" } ]
    }
  ]
}
```

## Segmented deletes (id allow-list)
```json
{
  "algorithm": "permit-overrides",
  "rules": [
    {"id":"delete_whitelist","effect":"permit","actions":["delete"],"resource":{"type":"doc","id":"A"}},
    {"id":"no_delete_others","effect":"deny","actions":["delete"],"resource":{"type":"doc"}}
  ]
}
```
