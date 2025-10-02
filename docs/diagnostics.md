# Policy diagnostics

RBACX provides two complementary diagnostics layers:

- **Schema validation** (`rbacx validate`) — checks that a policy (or each entry of a policy set) conforms to the official JSON Schema.
- **Heuristic linting** (`rbacx lint`) — analyzes policy structure for common authoring pitfalls **beyond** the schema.
- **One-shot convenience** (`rbacx check`) — runs validation first and, only if valid, runs the linter on the same input.

> The linter is intentionally heuristic. It aims for high-signal checks without heavy symbolic reasoning.

---

## Commands

### `rbacx validate`
Validate a single policy document or each member of a policy set against the JSON Schema.

### `rbacx lint`
Run non-schema checks that flag risky or inconsistent authoring patterns.

### `rbacx check`
Run **validate → lint** in one pass. If validation fails, linting is skipped.

---

## Inputs & outputs

### Inputs
- `--policy PATH|-` — path to a JSON/YAML file. Use `-` or omit the flag to read from **STDIN**.
- `--policyset` — interpret the input as a *policy set* (expects top-level `policies: [...]`).

### Outputs
- `--format json|text` — output format (default: `json`).
- `--strict` — for *lint*/**check**: return a non‑zero exit code when any lint issues are found.

### Lint‑specific
- `--require-attrs "subject:id,org;resource:type;:a,b"` — require that certain attribute **keys** appear in conditions by entity.  
  Entities: `subject`, `resource`, `action`, or empty for “any”. Right‑hand side is a comma‑separated list of required keys.

---

## Exit codes

| Code | Meaning |
|---:|---|
| 0 | OK |
| 2 | Usage error (bad arguments) |
| 3 | Lint issues found (only with `--strict`) |
| 4 | I/O error (file not found, decoding error) |
| 5 | Missing optional dependency (e.g., YAML or JSON Schema engine) |
| 6 | Schema validation errors |

---

## Lint checks

RBACX ships a simple linter to catch common authoring pitfalls:

- **MISSING_ID** — each rule should have a stable `id` for auditing.
- **DUPLICATE_ID** — rule ids must be unique within a policy.
- **EMPTY_ACTIONS** — avoid rules without actions.
- **BROAD_RESOURCE** — `resource.type` is `*` or missing; narrow the scope.
- **POTENTIALLY_UNREACHABLE** — with `first-applicable`, a later rule is shadowed because an earlier one with the same effect already covers its actions/resource.
- **ALWAYS_TRUE** — the condition is trivially true (e.g., `{"==":[X, X]}`); the rule may be overly broad.
- **ALWAYS_FALSE** — the condition is trivially false (e.g., `{"!=":[X, X]}`); the rule will never match.

> We intentionally avoid a generic `regex` operator to reduce ReDoS risk. If you add regex matching, prefer safe engines (like RE2) and enforce timeouts.

---

## Examples

### Validate
```bash
# Single policy (from file)
rbacx validate --policy policy.json

# Policy set (top-level "policies")
rbacx validate --policy policies.yaml --policyset

# Read from STDIN
cat policy.json | rbacx validate --policy -

# Human-readable
rbacx validate --policy policy.json --format text
```

**Output semantics**
- JSON: `[]` when valid, otherwise a list of error objects; for policy sets, each error may include `policy_index`.
- Text: prints `OK` when valid; otherwise one `SCHEMA` line per error, optionally with `[policy_index=N]`.

### Lint
```bash
# Lint a single policy
rbacx lint --policy policy.json

# Lint a policy set
rbacx lint --policy policies.yaml --policyset

# Human‑readable and strict (CI)
rbacx lint --policy policy.json --format text --strict

# Require attributes to appear in conditions
rbacx lint --policy policy.json --require-attrs "subject:id,org;resource:type"
```

**Output semantics**
- JSON: a list of issue objects. Typical fields: `code`, `message`, `path`, `policy_index` (for sets).
- Text: one line per issue, e.g.  
  `MISSING_ID [policy_index=0] rules[2].id: each rule should have a stable id`

### Check (validate → lint)
```bash
# Validate and lint in one go
rbacx check --policy policy.json

# CI‑friendly policy set run
rbacx check --policy policies.yaml --policyset --format text --strict

# With STDIN
cat policy.json | rbacx check --policy - --require-attrs "subject:id,org"
```

**Behavior**
- If validation produces any errors, the command exits with `6` (**SCHEMA_ERRORS**) and does not run lint.
- If validation passes, lint runs and prints issues; with `--strict`, the exit code is `3` (**LINT_ERRORS**) when issues are found.

---

## CI recommendations

```bash
# Fail the build on schema or lint problems, with readable logs
rbacx check --policy policy.json --format text --strict
# or:
rbacx validate --policy policy.json --format text
rbacx lint --policy policy.json --format text --strict
```