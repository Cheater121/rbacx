# Decision reasons

| Reason                    | Meaning                                  |
|---------------------------|------------------------------------------|
| `matched`                 | A permit rule matched                    |
| `explicit_deny`           | A deny rule matched                      |
| `condition_mismatch`      | Condition evaluated to False             |
| `condition_type_mismatch` | Incompatible types in a condition        |
| `resource_mismatch`       | Resource type/id/attrs didn't match      |
| `action_mismatch`         | Action not in rule's action list         |
| `no_match`                | No rule matched                          |

Operators include: `hasAll`, `hasAny`, `before/after/between`, plus standard comparisons.
