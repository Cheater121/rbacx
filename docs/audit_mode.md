# Audit mode

RBACX can **log authorization decisions** for observability **without enforcing** them.

## How it works

* Pass a **`DecisionLogSink`** implementation (e.g., `DecisionLogger`) to `Guard` via `logger_sink=...`.
* Each decision is emitted to the Python logger `rbacx.audit`. Set `as_json=True` to serialize the event as **JSON**; otherwise a compact text form (`decision {...}`) is logged. You can also control the log level via the `level` parameter.
* Optional sampling: either a single global `sample_rate` or **smart sampling** (`smart_sampling=True`) with category rates for `deny`, `permit_with_obligations`, `permit`.
* Redactions: pass explicit `redactions` or enable **default redactions** with `use_default_redactions=True`.
* Size bound: set `max_env_bytes` to cap serialized env after redactions.
* Redactions reuse obligation formats (e.g. `"mask_fields"`, `"redact_fields"`) and are applied *before* the event is logged; if a listed field is missing in the request context, the enforcer will still create it in the logged `env` with the appropriate placeholder (mask or `[REDACTED]`).
* **Redaction mode:** `DecisionLogger` forwards `redact_in_place` to the enforcer:

  * `redact_in_place=False` (default) — redact on a **copy** of `env` (non-mutating, safer by default).
  * `redact_in_place=True` — redact **in place** (fewer allocations; mutates the original `env`).
    Choose copy-by-default unless you explicitly need in-process sanitization with lower allocation pressure. This aligns with common guidance to avoid sensitive data in logs and use masking/redaction when needed.
* Prefer **structured logging** (e.g., JSON) and include enough context for auditability (what/when/where/source/outcome/actor) per typical audit record guidance.

## Example (framework-agnostic)

```python
import logging
from rbacx import Guard
from rbacx.logging.decision_logger import DecisionLogger

audit = logging.getLogger("rbacx.audit")
audit.setLevel(logging.INFO)
audit.addHandler(logging.StreamHandler())

decision_logger = DecisionLogger(
    as_json=True,
    use_default_redactions=True,                 # opt-in safe defaults
    smart_sampling=True,                         # category-aware sampling
    sample_rate=0.05,                            # fallback for plain permits
    category_sampling_rates={"permit": 0.05},    # leave deny/obligations at 1.0 (defaults)
    level=logging.INFO,
    redact_in_place=False,                       # set True only if you own the original env
    # optional size bound after redactions:
    max_env_bytes=64 * 1024,
)

policy = {"algorithm": "deny-overrides", "rules": []}
guard = Guard(policy, logger_sink=decision_logger)
```
