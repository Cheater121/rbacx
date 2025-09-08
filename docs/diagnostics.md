# Policy diagnostics

RBACX ships a simple linter to catch common authoring pitfalls:

- **MISSING_ID** – each rule should have a stable `id` for auditing.
- **DUPLICATE_ID** – ids must be unique per policy.
- **EMPTY_ACTIONS** – avoid rules without actions.
- **BROAD_RESOURCE** – `resource.type` is `*` or missing; narrow scope.
- **POTENTIALLY_UNREACHABLE** – with `first-applicable`, a later rule is unreachable if an earlier one with the same effect already covers its actions/resource.

Run:
```bash
rbacx lint --policy policy.json
```

> Note: this linter is heuristic by design. It focuses on high-signal checks without full SAT solving.

Additional heuristics:
- **ALWAYS_TRUE** – the condition is trivially true (e.g., `{"==":[X, X]}`); the rule may be overly broad.
- **ALWAYS_FALSE** – the condition is trivially false (e.g., `{"!=":[X, X]}`); the rule will never match.
> We intentionally avoid a `regex` operator to reduce ReDoS risk. If you add regex matching, prefer safe engines (RE2) and timeouts.
