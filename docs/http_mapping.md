
# Mapping Decision reasons to HTTP responses

A common mapping when using RBACX in web apps:

| Decision / reason               | HTTP code | Notes |
|---------------------------------|-----------|-------|
| `permit`                        | 200/204   | Proceed |
| `explicit_deny`                 | 403       | Hard deny |
| `no_match` / `no_match_policy`  | 403       | Deny-by-default |
| `condition_false`               | 403       | Policy matched but condition not satisfied |
| `condition_type_mismatch`       | 500       | Authoring/data issue; investigate |
| `action_mismatch`               | 403       | Rule exists but does not cover the action |
| `resource_mismatch`             | 404/403   | Prefer 404 for resource hiding; otherwise 403 |

> See OWASP guidance on logging and monitoring for how to record failures without leaking sensitive info.
