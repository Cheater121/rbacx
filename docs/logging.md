
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
- `sample_rate: float` — probability in [0..1] to log the event (legacy single-rate sampling).
- `redactions: list[dict]` — obligations-style redactions applied to `env` before logging. If provided (even `[]`), it is used exclusively.
- `use_default_redactions: bool` — when `True` **and** `redactions` is not provided, apply a conservative default set via the enforcer.
- `smart_sampling: bool` — enable category-aware sampling (`deny`, `permit_with_obligations`, `permit`).
- `category_sampling_rates: dict[str, float]` — per-category probabilities; unspecified categories fall back to `sample_rate`.
- `max_env_bytes: int` — cap the serialized size of the (already redacted) env; on exceed logs `{"_truncated": true, "size_bytes": N}`.
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

**Redaction priority:** `redactions` (if provided) → `use_default_redactions=True` → no redactions.


#### Example: opt-in defaults + smart sampling + size bound
```python
from rbacx.logging.decision_logger import DecisionLogger
sink = DecisionLogger(
    as_json=True,
    use_default_redactions=True,          # mask common PII/secrets via enforcer
    smart_sampling=True,                  # always log deny and permit-with-obligations
    sample_rate=0.05,                     # fallback for plain permits
    category_sampling_rates={"permit": 0.05},
    max_env_bytes=64 * 1024,              # bound serialized env size after redactions
)
```

### Default redaction set

Used **only** when `use_default_redactions=True` **and** `redactions` is not provided.
`redact_fields` values are replaced with `"[REDACTED]"`; `mask_fields` values use the placeholder `"***"`.

* **`redact_fields`** → `"[REDACTED]"`:

  * `subject.attrs.password`
  * `subject.attrs.token`
  * `subject.attrs.mfa_code`
  * `subject.attrs.email`
  * `subject.attrs.phone`
  * `resource.attrs.secret`
  * `context.headers.authorization`
  * `context.cookies` *(the whole cookies object is redacted)*

* **`mask_fields`** → `"***"`:

  * `context.ip`
