# Decision reasons

| Reason                    | Meaning                                           |
|---------------------------|---------------------------------------------------|
| `matched`                 | A permit rule matched                             |
| `explicit_deny`           | A deny rule matched                               |
| `condition_mismatch`      | Condition evaluated to False                      |
| `condition_type_mismatch` | Incompatible types in a condition                 |
| `condition_depth_exceeded` | Condition nesting depth exceeds `MAX_CONDITION_DEPTH` (50); rule skipped, fail-closed |
| `resource_mismatch`       | Resource type/id/attrs didn't match               |
| `action_mismatch`         | Action not in rule's action list                  |
| `no_match`                | No rule matched                                   |
| `obligation_failed`       | Obligations required by a permit rule were not met or failed verification (e.g., MFA) |

Operators include: `hasAll`, `hasAny`, `before/after/between`, plus standard comparisons.

---

## RuleTrace.skip_reason

When `explain=True` is passed to any evaluation method, each skipped rule's
`RuleTrace.skip_reason` uses the same vocabulary as `Decision.reason`:

| `skip_reason`               | When set                                                  |
|-----------------------------|-----------------------------------------------------------|
| `"action_mismatch"`         | Rule's `actions` list does not include the requested action |
| `"resource_mismatch"`       | Rule's `resource` constraint did not match                |
| `"condition_mismatch"`      | Rule's `condition` evaluated to `False`                   |
| `"condition_type_mismatch"` | Condition compared incompatible types                     |
| `"condition_depth_exceeded"`| Condition nesting exceeded `MAX_CONDITION_DEPTH`          |

`skip_reason` is `None` when `matched=True`.
