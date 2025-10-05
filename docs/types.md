# Types

Type semantics used during policy evaluation.

## Why types matter

* **Policies compare values.** If a system silently converts `"1"` ↔ `1` or parses dates from strings, rules may match when the author didn’t intend it (or fail when an integration changes formats). This is the core “implicit type coercion” problem.
* **Ecosystem reality.** Inputs often arrive as JSON with mixed types and date strings. Python itself has changed ISO-8601 parsing over time (e.g., `Z` support landed in 3.11), so relying on strings is convenient but version-sensitive.
* **Industry patterns.** Many validation/eval tools offer a *lenient* default and an opt-in *strict* path (e.g., Pydantic strict mode, JSON Schema coercion switches). The trade-off is ergonomics vs. guarantees.

**Design goal here:** keep the default **lax** because it is practical and predictable once you know the coercion rules, absorbs common input drift (e.g., numeric `1` vs. string `"1"`), reduces avoidable user/integration errors, and remains backward compatible. Provide **strict** for teams that want exact typing and loud failures on mismatches.

---

## Modes

* **Lax (default).** Pragmatic, input-tolerant behavior that accepts common real-world inputs (e.g., ISO date strings, epochs) and compares certain values via stringification where historically allowed. Predictable once you know the rules; helps prevent trivial mistakes like `1` vs `"1"` from breaking access. Also backward compatible with existing policies.
* **Strict.** No implicit coercions. Enable via `Guard(..., strict_types=True)`. The engine injects `__strict_types__ = true` into the evaluation env; cache keys differ accordingly. Choose this for predictability under audit, reviewability, and stronger invariants. (Analogous to “strict mode” in validators.)

---

## Resource matching

How `resource.type`, `resource.id`, and `resource.attrs` are compared:

| Field / check                | Lax (default)                    | Strict                       |
| ---------------------------- | -------------------------------- | ---------------------------- |
| `resource.type`              | compared as `str(value)`         | exact value **and** type     |
| `resource.id`                | compared as `str(value)`         | exact value **and** type     |
| `resource.attrs[k] == v`     | `str(lhs) == str(rhs)`           | exact equality `lhs == rhs`  |
| `resource.attrs[k] in [...]` | membership by stringified one-of | membership by exact equality |

**Implication:** in strict mode, `"1"` ≠ `1`, `"true"` ≠ `True`. Prefer normalizing types at ingestion rather than relying on stringification.

---

## Time operators

Operators: `before`, `after`, `between`.

* **Lax:** accepts `datetime` (naive → coerced to UTC), ISO 8601 strings (including `Z` / `+00:00`), and epoch numbers.
  *Note:* Python’s `datetime.fromisoformat` gained broader ISO coverage (notably `Z`) in 3.11; behavior differs on older runtimes.
* **Strict:** accepts **only** timezone-aware `datetime` (`tzinfo` required). ISO strings and epoch numbers are rejected with `ConditionTypeError`; engine converts this to `deny` with `reason="condition_type_mismatch"`.

For ISO background: `Z` denotes UTC in ISO-8601.

---

## Cache behavior

* **Lax:** cache keys unchanged (no flag in env).
* **Strict:** env includes `__strict_types__`, so keys differ; results are isolated by mode.

---

## When to use which

**Stick with lax** if:

* you are onboarding legacy systems and want minimal friction;
* inputs arrive as “stringly-typed” JSON (IDs as strings, dates as ISO) and policies already depend on that leniency;
* you want the engine to absorb minor input drift and prevent trivial typing mistakes from breaking access.

**Prefer strict** if:

* you need *deterministic* matches (no accidental `"1"` vs `1` equality);
* you review policies for compliance/security and want mismatches to fail loud;
* you rely on time comparisons across services/runtimes and want to ban string/epoch ambiguity.

This mirrors common practice: lenient by default for ergonomics and error-reduction, strict when correctness and auditability dominate.

---

## Engine toggle

```py
from rbacx import Guard

# Lax (default)
g1 = Guard(policy)

# Strict
g2 = Guard(policy, strict_types=True)
```

---

## Authoring guidance

* Pass **aware `datetime`** objects in time conditions when strict is enabled.
* Normalize `resource.type`, `resource.id`, and `resource.attrs` types at the boundary (API/deserializer).
* Keep policies mode-agnostic where possible; choose the mode at engine construction.

---

## FAQ

**Why is lax the default?**
It is practical, predictable given the documented coercions, reduces integration/user errors (e.g., `1` vs `"1"`), and preserves existing behavior. Teams can enable strict when ready.

**Does strict change decision algorithms?**
No. It only changes type handling (comparisons and date parsing).

**Will strict break my cache?**
Keys are different in strict (by design) but unchanged in lax. You can run both modes side-by-side.
