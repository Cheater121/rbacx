# Audit mode

RBACX can **log authorization decisions** for observability **without enforcing** them.

## How it works
- Pass a `DecisionLogger` to `Guard` via `logger_sink=...`.
- Each decision is emitted as a **structured JSON** event to the Python logger `rbacx.audit`.
- Optional sampling (`sample_rate`) helps manage log volume in high-traffic environments.
- Redactions reuse obligation formats (e.g. `"mask_fields"`, `"redact_fields"`) and are applied *before* the event is logged.
- It is best practice to log security-relevant events using structured/centralized logs, and to avoid logging sensitive fields.

## Example (framework-agnostic)

```python
import logging
from rbacx.core.engine import Guard
from rbacx.logging.decision_logger import DecisionLogger

audit = logging.getLogger("rbacx.audit")
audit.setLevel(logging.INFO)
audit.addHandler(logging.StreamHandler())

decision_logger = DecisionLogger(
    sample_rate=0.1,
    redactions=[{"type": "mask_fields", "fields": ["subject.email", "resource.attrs.card"]}],
)

policy = {"algorithm":"deny-overrides","rules":[]}

guard = Guard(policy, logger_sink=decision_logger)
```
