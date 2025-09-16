# Audit mode

RBACX can **log authorization decisions** for observability **without enforcing** them.

## How it works
- Pass a **`DecisionLogSink`** implementation (e.g., `DecisionLogger`) to `Guard` via `logger_sink=...`.
- Each decision is emitted to the Python logger `rbacx.audit`. Set `as_json=True` to serialize the event as **JSON**; otherwise a compact text form (`decision {...}`) is logged. You can also control the log level via the `level` parameter.
- Optional sampling (`sample_rate`) helps manage log volume in high-traffic environments.
- Redactions reuse obligation formats (e.g. `"mask_fields"`, `"redact_fields"`) and are applied *before* the event is logged; if a listed field is missing in the request context, the enforcer will still create it in the logged `env` with the appropriate placeholder (mask or `[REDACTED]`).
- It is best practice to log security-relevant events using structured/centralized logs, and to avoid logging sensitive fields.

## Example (framework-agnostic)

```python
import logging
from rbacx import Guard
from rbacx.logging.decision_logger import DecisionLogger

audit = logging.getLogger("rbacx.audit")
audit.setLevel(logging.INFO)
audit.addHandler(logging.StreamHandler())

decision_logger = DecisionLogger(
    sample_rate=0.1,
    redactions=[{"type": "mask_fields", "fields": ["subject.email", "resource.attrs.card"]}],
    as_json=True,              # new: emit JSON
    level=logging.INFO,        # new: configurable log level
)

policy = {"algorithm":"deny-overrides","rules":[]}

guard = Guard(policy, logger_sink=decision_logger)
```
