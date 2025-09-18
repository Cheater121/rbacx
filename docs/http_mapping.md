# Mapping Decision reasons to HTTP responses

A common mapping when using RBACX in web apps:

| Decision / reason                         | HTTP code | Notes |
|-------------------------------------------|-----------|-------|
| `permit`                                  | 200/204   | Proceed |
| `explicit_deny`                           | 403       | Hard deny |
| `no_match` / `no_match_policy`            | 403       | Deny-by-default |
| `condition_mismatch`                      | 403       | Policy matched but condition evaluated to False |
| `condition_type_mismatch`                 | 500       | Authoring/data issue; investigate |
| `obligation_failed`                       | 403 (or 401 if an auth challenge) | Permit was gated by obligations (e.g., MFA) and they were not fulfilled or failed verification. If the decision includes a `challenge` tied to authentication, you MAY return 401 and include the appropriate challenge header; otherwise return 403. |
| `action_mismatch`                         | 403       | Rule exists but does not cover the action |
| `resource_mismatch`                       | 404/403   | Prefer 404 for resource hiding; otherwise 403 |

> See OWASP guidance on logging and monitoring for how to record failures without leaking sensitive info.
