
# Obligations & Challenges

This page documents the built-in obligation types enforced by `BasicObligationChecker` and shows how to extend the checker with custom policies (e.g., geo-fencing). It also clarifies how to target obligations to a specific decision effect (`permit` vs `deny`) and how `challenge` hints are surfaced to the PEP layer.

## Obligations and deny decisions

When the engine produces a `deny` decision, `Decision.obligations` is always
`[]` — obligations from the matched deny rule are intentionally discarded.

This is a deliberate security decision aligned with XACML recommendations:

* **Obligations are side effects** (log access, mask data, add watermark,
  trigger a webhook). Executing them on a denied request can cause unexpected
  behaviour, information leakage, or policy bypass.
* **`deny` is a terminal state** — under `deny-overrides` the loop breaks on
  the first matching deny, so evaluation may be incomplete and the context
  not fully resolved.
* **Predictability** — the engine guarantees `obligations` is always a `list`
  and is non-empty only on `permit`.

If you need the PEP to know *why* a request was denied, use `Decision.reason`
and `Decision.rule_id`. For authentication challenges (e.g. `WWW-Authenticate`
headers on 401 responses) use the dedicated `Decision.challenge` field, which
is populated by `require_mfa`, `http_challenge`, and similar obligation types
when they fire on a *permit* decision that fails an obligation check.

## Compatibility

The checker accepts both legacy and modern raw decision shapes:

* **Legacy:** `{"decision": "permit" | "deny", "obligations": [...]}`
* **Modern:** `{"effect": "permit" | "deny", "allowed": bool, "obligations": [...]}`

Rules of thumb:

* Any **non-`permit`** decision fails closed: `(ok=False, challenge=None)`.
* When effect is **`permit`**, obligations targeted at `permit` are evaluated; if any fails, `(ok=False, challenge=...)`.
* Obligations can explicitly target an effect via `on: "permit" | "deny"`; those not matching the current effect are ignored.

## Obligations targeting `deny`

Obligations may target the **`deny`** branch via `on: "deny"`. This is useful to surface a machine-readable `challenge` (e.g., `http_basic`) even when the PDP already decided to deny. The PEP can then translate it into `WWW-Authenticate` headers or other UX.

## Built-in obligation types

> Unless noted, these apply when `on: "permit"`.

* `require_mfa` → `challenge="mfa"` when `context.attrs["mfa"]` is falsy.
* `require_level` (`attrs.min`) → `challenge="step_up"` when `context.attrs["auth_level"] < min`.
* `http_challenge` (`on: permit|deny`, `attrs.scheme` = `Basic|Bearer|Digest`) →
  `challenge="http_basic" | "http_bearer" | "http_digest"`; unknown/omitted scheme → `http_auth`.
* `require_consent` (optional `attrs.key`) → `challenge="consent"` when consent is missing.

  * With a key: expect `context.attrs["consent"][key] is True`.
  * Without a key: expect any truthy `context.attrs["consent"]`.
* `require_terms_accept` → `challenge="tos"` when `context.attrs["tos_accepted"]` is falsy.
* `require_captcha` → `challenge="captcha"` when `context.attrs["captcha_passed"]` is falsy.
* `require_reauth` (`attrs.max_age`) → `challenge="reauth"` when `context.attrs["reauth_age_seconds"] > max_age`.
* `require_age_verified` → `challenge="age_verification"` when `context.attrs["age_verified"]` is falsy.

## Policy examples

### YAML — MFA on `permit`

```yaml
# A permit rule that requires MFA before access is actually granted.
obligations:
  - on: permit
    type: require_mfa
```

### JSON — HTTP challenge on `deny`

```json
{
  "obligations": [
    {
      "on": "deny",
      "type": "http_challenge",
      "attrs": { "scheme": "Basic" }
    }
  ]
}
```

### YAML — Geo-fencing (custom extension example)

```yaml
# Example obligation we will implement via a custom checker:
# Allow only if user's geo is in the allowed set.
obligations:
  - on: permit
    type: require_geo
    attrs:
      allow: ["EU", "US"]
```

> Expected context for geo: `context.attrs["geo"]` should contain a short region code (e.g., `"EU"`, `"US"`, `"APAC"`).

## Extending the checker (custom obligations)

To add your own obligation types (e.g., `require_geo`), subclass `BasicObligationChecker` and handle your `type`. Always call `super().check(...)` first to preserve built-ins and fail-closed semantics.

```python
# src/myapp/obligations.py
from rbacx.core.obligations import BasicObligationChecker

class CustomObligationChecker(BasicObligationChecker):
    def check(self, decision, context):
        # Let the base checker evaluate built-ins first.
        ok, ch = super().check(decision, context)
        if not ok:
            return ok, ch

        # Determine current effect in the same manner as the base checker does:
        effect = decision.get("effect")
        if effect is None:
            effect = "permit" if decision.get("decision") == "permit" else "deny"
        if effect not in ("permit", "deny"):
            effect = "deny"  # fail-closed

        ctx = getattr(context, "attrs", context) or {}
        obligations = decision.get("obligations") or []

        for ob in obligations:
            if (ob or {}).get("on", "permit") != effect:
                continue
            if (ob or {}).get("type") == "require_geo":
                allow_list = set(((ob.get("attrs") or {}).get("allow") or []))
                if not allow_list:
                    # No allow-list means fail-closed
                    return False, "geo"
                if ctx.get("geo") not in allow_list:
                    return False, "geo"

        return True, None
```

Then wire your checker into the Guard (where you construct your PDP/PEP integration). The Guard should consume `(ok, challenge)` and, on failure, flip `permit → deny`, adding the `challenge` to the final `Decision`.


## Conditional obligations

An obligation may carry an optional ``condition`` field evaluated against the
full request env before the obligation is enforced.  When the condition is
``False`` the obligation is silently skipped; when the field is absent the
behaviour is unchanged.

```json
{
  "type": "require_mfa",
  "on": "permit",
  "condition": {"==": [{"attr": "resource.attrs.sensitivity"}, "high"]}
}
```

The condition supports the full DSL — comparisons, collections, time operators,
logical operators, and ``attr`` references to ``subject``, ``resource``,
``action``, and ``context``.

### Examples

**MFA only for high-sensitivity resources:**

```json
{
  "obligations": [
    {
      "type": "require_mfa",
      "on": "permit",
      "condition": {"==": [{"attr": "resource.attrs.sensitivity"}, "high"]}
    }
  ]
}
```

**Step-up auth only for premium users:**

```json
{
  "obligations": [
    {
      "type": "require_level",
      "on": "permit",
      "attrs": {"min": 2},
      "condition": {"==": [{"attr": "subject.attrs.tier"}, "premium"]}
    }
  ]
}
```

**Mixed — conditional and unconditional obligations together:**

```json
{
  "obligations": [
    {
      "type": "require_mfa",
      "on": "permit",
      "condition": {"==": [{"attr": "resource.attrs.sensitivity"}, "high"]}
    },
    {
      "type": "require_terms_accept",
      "on": "permit"
    }
  ]
}
```

MFA is required only when the resource is high-sensitivity; ToS acceptance
is always required on permit.

### Error handling

If the condition raises a type error or exceeds the depth limit, the obligation
is **skipped** (fail-safe).  A broken condition never causes the obligation to
fire unexpectedly.

---
## Context contract (quick reference)

The checker reads the following `context.attrs[...]` keys when relevant:

* `mfa: bool`
* `auth_level: int`
* `consent: bool | {str: bool}`
* `tos_accepted: bool`
* `captcha_passed: bool`
* `reauth_age_seconds: int`
* `age_verified: bool`
* `geo: str` (custom example)


## Conditional obligations

An obligation can carry an optional `condition` field.  The obligation is
enforced **only when the condition evaluates to `True`** against the full
evaluation environment (`subject`, `resource`, `action`, `context`).
All operators available in rule conditions are supported.

### Example — MFA only for sensitive resources

```json
{
  "rules": [
    {
      "id": "doc-read",
      "effect": "permit",
      "actions": ["read"],
      "resource": {"type": "doc"},
      "obligations": [
        {
          "type": "require_mfa",
          "on": "permit",
          "condition": {"==": [{"attr": "resource.attrs.sensitivity"}, "high"]}
        }
      ]
    }
  ]
}
```

With this policy, MFA is required only when `resource.attrs.sensitivity == "high"`.
Requests for low-sensitivity documents are permitted without MFA.

### Example — step-up auth for premium users

```json
{
  "type": "require_level",
  "on": "permit",
  "attrs": {"min": 2},
  "condition": {"==": [{"attr": "subject.attrs.tier"}, "premium"]}
}
```

### Condition namespace

Inside an obligation condition, the same attribute paths available in rule
conditions are accessible:

| Path | Description |
|---|---|
| `subject.id` | Subject identifier |
| `subject.roles` | Subject role list |
| `subject.attrs.*` | Subject attributes |
| `resource.type` | Resource type |
| `resource.id` | Resource identifier |
| `resource.attrs.*` | Resource attributes |
| `context.*` | Context attributes |

### Fail-safe behaviour

If a condition raises a type error (`ConditionTypeError`) or exceeds the
nesting depth limit (`ConditionDepthError`), the obligation is **skipped**
— not enforced.  This prevents a broken condition from inadvertently
blocking all access.

Obligations without a `condition` field behave exactly as before.

## Notes & best practices

* Keep obligation handlers **pure** (no I/O) and quick; they run in the request path.
* Use `on: "deny"` to add *diagnostics/UX* to denials (e.g., prompt client re-auth).
* When parsing numeric attrs (e.g., `min`, `max_age`), default invalid values to **0** and fail closed.
* Unknown `type` values should be treated as **advice** and ignored by the checker unless you explicitly implement them.
