
# Audit mode

RBACX can log decisions for observability without enforcing them.

## How it works
- `DecisionLogger(sample_rate=..., redactions=[...])` writes JSON payloads to logger `rbacx.audit`.
- Redactions reuse obligations (e.g., `mask_fields`, `redact_fields`) and apply to the env before logging.
- Use sampling in accordance with OWASP Logging Cheat Sheet: log security-relevant events and avoid sensitive data. Configure JSON logs. 

## Example (FastAPI)
```python
from rbacx.core.engine import Guard
from rbacx.logging.decision_logger import DecisionLogger

decision_logger = DecisionLogger(sample_rate=0.1, redactions=[{"type":"mask_fields","fields":["subject.email","resource.attrs.card"]}])
guard = Guard(policy, decision_logger=decision_logger)
```

See also OWASP logging guidance.
