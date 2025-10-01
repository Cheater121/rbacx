# tests/unit/logging/test_decision_logger_redactions_optin.py

import json
import logging
from typing import List

from rbacx.logging.decision_logger import _DEFAULT_REDACTIONS, DecisionLogger


class _MemoryHandler(logging.Handler):
    """In-memory log handler to capture emitted messages."""

    def __init__(self) -> None:
        super().__init__()
        self.messages: List[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(self.format(record))


def _setup_logger(name: str = "rbacx.audit.test", level: int = logging.INFO):
    """Create an isolated logger with a memory handler."""
    logger = logging.getLogger(name)
    logger.handlers[:] = []  # reset handlers
    logger.propagate = False
    logger.setLevel(level)
    handler = _MemoryHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    return logger, handler


def _payload():
    """Representative payload with sensitive fields that should be redacted when enabled."""
    return {
        "env": {
            "subject": {
                "id": "u1",
                "attrs": {
                    "email": "user@example.com",
                    "token": "t-123",
                    "password": "p",
                    "mfa_code": "000000",
                    "phone": "+10000000000",
                },
            },
            "resource": {"type": "doc", "id": "42", "attrs": {"secret": "s"}},
            "context": {
                "ip": "10.0.0.5",
                "headers": {"authorization": "Bearer abc"},
                "cookies": {"sid": "C"},
            },
        },
        "decision": "permit",
        "allowed": True,
        "policy_id": "p1",
        "rule_id": "r1",
        "reason": None,
    }


def test_no_redactions_by_default_json():
    """By default, no redactions are applied (backward compatibility)."""
    logger, mem = _setup_logger()
    dl = DecisionLogger(logger_name=logger.name, as_json=True)  # defaults: no redactions
    dl.log(_payload())

    assert len(mem.messages) == 1
    out = json.loads(mem.messages[0])
    env = out["env"]
    # Sensitive values remain unchanged by default
    assert env["subject"]["attrs"]["email"] == "user@example.com"
    assert env["subject"]["attrs"]["token"] == "t-123"
    assert env["subject"]["attrs"]["password"] == "p"
    assert env["subject"]["attrs"]["mfa_code"] == "000000"
    assert env["subject"]["attrs"]["phone"] == "+10000000000"
    assert env["resource"]["attrs"]["secret"] == "s"
    assert env["context"]["headers"]["authorization"] == "Bearer abc"
    assert env["context"]["cookies"]["sid"] == "C"
    assert env["context"]["ip"] == "10.0.0.5"


def test_default_redactions_enabled_opt_in():
    """Opting in to default redactions should mask/redact sensitive fields."""
    logger, mem = _setup_logger()
    dl = DecisionLogger(logger_name=logger.name, as_json=True, use_default_redactions=True)
    dl.log(_payload())

    assert len(mem.messages) == 1
    out = json.loads(mem.messages[0])
    env = out["env"]

    # redact_fields: value is replaced with "[REDACTED]"
    assert env["subject"]["attrs"].get("email") == "[REDACTED]"
    assert env["subject"]["attrs"].get("token") == "[REDACTED]"
    assert env["subject"]["attrs"].get("password") == "[REDACTED]"
    assert env["subject"]["attrs"].get("mfa_code") == "[REDACTED]"
    assert env["subject"]["attrs"].get("phone") == "[REDACTED]"
    assert env["resource"]["attrs"].get("secret") == "[REDACTED]"
    assert env["context"]["headers"].get("authorization") == "[REDACTED]"
    assert env["context"].get("cookies") == "[REDACTED]"

    # mask_fields: replaced with the provided placeholder
    assert env["context"].get("ip") == "***"


def test_explicit_empty_redactions_disable_defaults_even_if_flag_true():
    """Explicit empty list must disable defaults even if the flag is True."""
    logger, mem = _setup_logger()
    dl = DecisionLogger(
        logger_name=logger.name,
        as_json=True,
        redactions=[],  # explicit empty
        use_default_redactions=True,  # must be ignored
    )
    dl.log(_payload())

    assert len(mem.messages) == 1
    out = json.loads(mem.messages[0])
    env = out["env"]
    # Everything should pass through unchanged
    assert env["subject"]["attrs"]["email"] == "user@example.com"
    assert env["context"]["ip"] == "10.0.0.5"


def test_custom_redactions_override_defaults():
    """Custom redactions must be used exclusively when provided."""
    logger, mem = _setup_logger()
    custom = [{"type": "mask_fields", "fields": ["context.ip"], "placeholder": "X"}]
    dl = DecisionLogger(
        logger_name=logger.name,
        as_json=True,
        redactions=custom,  # provided → takes precedence
        use_default_redactions=True,  # ignored because custom provided
    )
    dl.log(_payload())

    assert len(mem.messages) == 1
    out = json.loads(mem.messages[0])
    env = out["env"]
    assert env["context"]["ip"] == "X"
    # Other fields are untouched
    assert env["subject"]["attrs"]["email"] == "user@example.com"
    assert env["resource"]["attrs"]["secret"] == "s"


def test_sampling_zero_drops_all():
    """sample_rate=0.0 must drop all log lines."""
    logger, mem = _setup_logger()
    dl = DecisionLogger(logger_name=logger.name, as_json=True, sample_rate=0.0)
    for _ in range(10):
        dl.log(_payload())
    assert len(mem.messages) == 0


def test_sampling_probabilistic_logs_when_random_low(monkeypatch):
    """When random is below sample_rate, the record is logged."""
    logger, mem = _setup_logger()
    dl = DecisionLogger(logger_name=logger.name, as_json=True, sample_rate=0.01)

    # Force random.random() to return 0.0 so it is always <= sample_rate
    monkeypatch.setattr("random.random", lambda: 0.0)

    dl.log(_payload())
    assert len(mem.messages) == 1


def test_default_specs_constant_is_reasonable():
    """Sanity checks for DEFAULT_REDACTIONS content (guard against accidental changes)."""
    serialized = json.dumps(_DEFAULT_REDACTIONS)
    assert "subject.attrs.password" in serialized
    assert "subject.attrs.token" in serialized
    assert "subject.attrs.email" in serialized
    assert "resource.attrs.secret" in serialized
    assert "context.headers.authorization" in serialized
    assert "context.cookies" in serialized
    assert "context.ip" in serialized
