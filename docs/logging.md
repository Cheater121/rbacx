
# Logging configuration

RBACX uses Python's standard `logging` and **does not** configure handlers for you.

## Console logging (dictConfig)

```python
import logging, logging.config
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
import logging, logging.config
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
import logging, logging.config, os
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
