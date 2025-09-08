
# Time operators

Operators: `before`, `after`, `between` using ISO-8601 strings (e.g., `2025-09-07T10:00:00Z`).

- Parser prefers `datetime.fromisoformat`, normalizing `Z` to `+00:00`.
- Falls back to `dateutil.isoparse` if `rbacx[dates]` installed.

Examples:
```json
{"before": [ {"attr":"context.now"}, "2025-12-31T23:59:59Z" ]}
{"between": [ {"attr":"context.now"}, ["2025-01-01T00:00:00Z","2025-12-31T23:59:59Z"] ]}
```
