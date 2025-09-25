# Obligations & Challenges (RBACX 1.1+)

This page describes the built-in obligation types enforced by the **BasicObligationChecker**
and how to extend them with custom checks.

## Compatibility note

The checker remains compatible with the legacy raw-decision shape using string key
`decision` ("permit"|"deny"). For any non-"permit" value it **fails closed** and returns
`(False, None)`. When `decision == "permit"`, obligation checks run for the current effect.
If the legacy key is absent, the checker falls back to `effect/allowed`.

## Obligations targeting `deny`

Obligations may target the `deny` branch via `on: "deny"`. This is useful to surface
a machine-readable `challenge` (e.g., `http_basic`) even when the effect is already `deny`.
PEP can then translate it to `WWW-Authenticate` headers or other UX.

## Built-in obligation types

- `require_mfa` (on: permit) → `mfa`
- `require_level` (on: permit, `attrs.min`) → `step_up`
- `http_challenge` (on: permit|deny, `attrs.scheme`) → `http_basic` / `http_bearer` / `http_digest` / `http_auth`
- `require_consent` (on: permit, optional `attrs.key`) → `consent`
- `require_terms_accept` (on: permit) → `tos`
- `require_captcha` (on: permit) → `captcha`
- `require_reauth` (on: permit, `attrs.max_age`) → `reauth`
- `require_age_verified` (on: permit) → `age_verification`

### Policy snippets

```yaml
# MFA on permit
obligations:
  - on: permit
    type: require_mfa
```

```yaml
# HTTP challenge on deny (PEP sets WWW-Authenticate)
obligations:
  - on: deny
    type: http_challenge
    attrs:
      scheme: Basic
```

## Extending the checker

Subclass and add your own `type` handlers; call `super().check()` first and short-circuit if it fails.
