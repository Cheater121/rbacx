
# Logging configuration

RBACX uses Python's standard `logging` and **does not** configure handlers for you.

## Console logging (dictConfig)

```python
import logging.config
LOGGING = {
  "version": 1,
  "disable_existing_loggers": False,
  "formatters": {"console": {"format": "%(asctime)s %(levelname)s %(name)s: %(message)s"}},
  "handlers": {"console": {"class": "logging.StreamHandler", "formatter": "console"}},
  "root": {"level": "INFO", "handlers": ["console"]},
}
logging.config.dictConfig(LOGGING)
```

## Rotating file logs

```python
import logging.config
LOGGING = {
  "version": 1, "disable_existing_loggers": False,
  "formatters": {"plain": {"format": "%(asctime)s %(levelname)s %(name)s: %(message)s"}},
  "handlers": {"file": {"class": "logging.handlers.RotatingFileHandler", "filename": "app.log", "maxBytes": 5_000_000, "backupCount": 3, "encoding": "utf-8", "formatter": "plain"}},
  "root": {"level": "INFO", "handlers": ["file"]},
}
logging.config.dictConfig(LOGGING)
```

## JSON logs (python-json-logger)

```bash
pip install "rbacx[jsonlog]"
```
```python
import logging.config
LOGGING = {
  "version": 1, "disable_existing_loggers": False,
  "formatters": {"json": {"class": "pythonjsonlogger.jsonlogger.JsonFormatter", "format": "%(asctime)s %(levelname)s %(name)s %(message)s %(trace_id)s"}},
  "handlers": {"console": {"class": "logging.StreamHandler", "formatter": "json"}},
  "root": {"level": "INFO", "handlers": ["console"]},
}
logging.config.dictConfig(LOGGING)
```

## Request tracing (trace_id)

Use `rbacx.logging.context.TraceIdFilter` to inject `trace_id` into records.
- ASGI (FastAPI, Litestar): `rbacx.adapters.asgi_logging.TraceIdMiddleware`.
- Django: `rbacx.adapters.django.trace.TraceIdMiddleware`.
- Flask: hooks in the example manage `X-Request-ID` header.

## RBACX Decision Logger (audit sink)

`rbacx.logging.decision_logger.DecisionLogger` implements the `DecisionLogSink` port. It can emit decision events either as text or JSON and supports sampling and redactions.

**Options:**
- `sample_rate: float` — probability in [0..1] to log the event.
- `redactions: list[dict]` — obligations-style redactions applied to `env` before logging.
- `as_json: bool` — when `True`, serialize the event to JSON; otherwise logs as `"decision {payload}"`.
- `level: int` — Python logging level used for the event (defaults to `logging.INFO`).
- `redact_in_place: bool = False` — controls how redactions are applied to env:
  - `False` (default): redact on a copy (no mutation of the original environment).
  - `True`: redact in place (fewer allocations; mutates the original env).

**Examples:**
```python
import logging
from rbacx.logging.decision_logger import DecisionLogger

audit = logging.getLogger("rbacx.audit")
audit.setLevel(logging.INFO)
audit.addHandler(logging.StreamHandler())

logger_sink = DecisionLogger(
    sample_rate=0.1,  # about 10% of events will be logged
    as_json=True,
    level=logging.INFO,
    redactions=[{"type": "mask_fields", "fields": ["subject.attrs.ssn"], "placeholder": "***"}],
)

# In-place redaction (mutates env), useful to minimize allocations on hot paths
inplace_sink = DecisionLogger(
    sample_rate=1.0,
    as_json=True,
    level=logging.INFO,
    redactions=[{"type": "redact_fields", "fields": ["resource.attrs.secret"]}],
    redact_in_place=True,  # mutate env instead of copying
)
```
