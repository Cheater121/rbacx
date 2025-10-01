# tests/unit/logging/test_decision_logger_sampling_and_size.py

import json
import logging
from typing import List

from rbacx.logging.decision_logger import DecisionLogger


class _MemoryHandler(logging.Handler):
    """In-memory log handler to capture emitted messages."""

    def __init__(self) -> None:
        super().__init__()
        self.messages: List[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(self.format(record))


def _setup_logger(name: str = "rbacx.audit.test.sampling", level: int = logging.INFO):
    """Create an isolated logger with a memory handler to avoid global side effects."""
    logger = logging.getLogger(name)
    logger.handlers[:] = []
    logger.propagate = False
    logger.setLevel(level)
    h = _MemoryHandler()
    h.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(h)
    return logger, h


def _payload(
    *,
    decision: str = "permit",
    allowed: bool = True,
    with_obligations: bool = False,
    huge_token: bool = False,
    huge_extra: bool = False,
):
    """Build a representative payload with optional obligations and large fields."""
    token_val = "x" * 10000 if huge_token else "t-123"
    env = {
        "subject": {"id": "u1", "attrs": {"email": "user@example.com", "token": token_val}},
        "resource": {"type": "doc", "id": "42", "attrs": {"secret": "s"}},
        "context": {"ip": "10.0.0.5", "headers": {"authorization": "Bearer abc"}},
    }
    if huge_extra:
        env["context"]["extra"] = "Z" * 20000
    payload = {
        "env": env,
        "decision": decision,
        "allowed": allowed,
        "policy_id": "p1",
        "rule_id": "r1",
        "reason": None,
    }
    if with_obligations:
        payload["obligations"] = [{"type": "reauth"}]
    return payload


# ------------------------ smart sampling (opt-in) ------------------------


def test_smart_sampling_disabled_rate_zero_drops_all_even_deny(monkeypatch):
    """With smart_sampling=False, sample_rate=0.0 drops everything — including DENY."""
    logger, h = _setup_logger()
    dl = DecisionLogger(
        logger_name=logger.name, as_json=True, sample_rate=0.0, smart_sampling=False
    )

    # Force a low random value; despite that, rate=0.0 must drop the log.
    monkeypatch.setattr("random.random", lambda: 0.0, raising=True)

    dl.log(_payload(decision="deny", allowed=False))
    assert len(h.messages) == 0


def test_smart_sampling_enabled_logs_deny_even_with_rate_zero():
    """With smart_sampling=True, default category rates log all DENY regardless of sample_rate."""
    logger, h = _setup_logger()
    dl = DecisionLogger(
        logger_name=logger.name,
        as_json=True,
        sample_rate=0.0,  # legacy would drop all
        smart_sampling=True,  # default category rates: {"deny": 1.0, "permit_with_obligations": 1.0}
    )

    dl.log(_payload(decision="deny", allowed=False))
    assert len(h.messages) == 1
    out = json.loads(h.messages[0])
    assert out["decision"] == "deny"
    assert out["allowed"] is False


def test_smart_sampling_enabled_logs_permit_with_obligations_even_with_rate_zero():
    """With smart_sampling=True, default category rates log all PERMIT with obligations."""
    logger, h = _setup_logger()
    dl = DecisionLogger(
        logger_name=logger.name,
        as_json=True,
        sample_rate=0.0,
        smart_sampling=True,
    )

    dl.log(_payload(decision="permit", allowed=True, with_obligations=True))
    assert len(h.messages) == 1
    out = json.loads(h.messages[0])
    assert out["decision"] == "permit"
    assert out["allowed"] is True
    assert out.get("obligations")


def test_smart_sampling_enabled_drops_plain_permit_when_rate_zero(monkeypatch):
    """With smart_sampling=True and sample_rate=0.0, plain PERMIT (no obligations) is dropped."""
    logger, h = _setup_logger()
    dl = DecisionLogger(
        logger_name=logger.name,
        as_json=True,
        sample_rate=0.0,
        smart_sampling=True,
    )

    # random value should not matter because effective rate for "permit" falls back to 0.0
    monkeypatch.setattr("random.random", lambda: 0.99, raising=True)

    dl.log(_payload(decision="permit", allowed=True, with_obligations=False))
    assert len(h.messages) == 0


def test_category_sampling_rates_overrides_permit(monkeypatch):
    """Category-specific rates should override the global sample_rate for 'permit'."""
    logger, h = _setup_logger()

    # Case A: override 'permit' to 1.0 (log), even if global sample_rate=0.0
    dl_log = DecisionLogger(
        logger_name=logger.name,
        as_json=True,
        sample_rate=0.0,
        smart_sampling=True,
        category_sampling_rates={"deny": 1.0, "permit_with_obligations": 1.0, "permit": 1.0},
    )
    monkeypatch.setattr("random.random", lambda: 0.99, raising=True)
    dl_log.log(_payload(decision="permit", allowed=True))
    assert len(h.messages) == 1
    h.messages.clear()

    # Case B: override 'permit' to 0.0 (drop), even if global sample_rate=1.0
    dl_drop = DecisionLogger(
        logger_name=logger.name,
        as_json=True,
        sample_rate=1.0,
        smart_sampling=True,
        category_sampling_rates={"deny": 1.0, "permit_with_obligations": 1.0, "permit": 0.0},
    )
    monkeypatch.setattr("random.random", lambda: 0.0, raising=True)
    dl_drop.log(_payload(decision="permit", allowed=True))
    assert len(h.messages) == 0


# ------------------------ max_env_bytes (opt-in) ------------------------


def test_max_env_bytes_truncates_when_over_limit():
    """When redacted env still exceeds the limit, a placeholder object is logged."""
    logger, h = _setup_logger()
    dl = DecisionLogger(
        logger_name=logger.name,
        as_json=True,
        use_default_redactions=True,  # leave some non-redacted fields to ensure size > limit
        max_env_bytes=500,
    )

    dl.log(_payload(huge_extra=True))
    assert len(h.messages) == 1
    out = json.loads(h.messages[0])
    assert out["env"].get("_truncated") is True
    assert isinstance(out["env"].get("size_bytes"), int)


def test_max_env_bytes_applies_after_redactions_so_huge_token_does_not_force_truncation():
    """Redactions are applied before size check, so a huge token should be redacted and not trigger truncation."""
    logger, h = _setup_logger()
    dl = DecisionLogger(
        logger_name=logger.name,
        as_json=True,
        use_default_redactions=True,  # will redact token/email/secret/authorization
        max_env_bytes=1024,
    )

    dl.log(_payload(huge_token=True))
    assert len(h.messages) == 1
    out = json.loads(h.messages[0])
    assert "_truncated" not in out["env"]
    assert out["env"]["subject"]["attrs"]["token"] == "[REDACTED]"


def test_serialization_error_falls_back_to_original_env(monkeypatch):
    """If json.dumps raises during size check, the logger must fall back to the original env and still emit a record."""
    import rbacx.logging.decision_logger as dlmod

    logger, h = _setup_logger()

    dl = dlmod.DecisionLogger(
        logger_name=logger.name,
        as_json=False,  # avoid re-serializing the whole payload to JSON (would fail again)
        max_env_bytes=10,  # force entering the size-check branch
        smart_sampling=False,  # irrelevant for this test, keep legacy path
    )

    # Use a non-JSON-serializable value in env to trigger json.dumps failure inside the size-check try/except
    payload = {
        "env": {"context": {"bad": {1, 2, 3}}},  # set is not JSON-serializable
        "decision": "permit",
        "allowed": True,
    }

    # Force json.dumps used by the logger to raise (simulate serialization error)
    def boom(*args, **kwargs):
        raise ValueError("serialization failure")

    monkeypatch.setattr(dlmod.json, "dumps", boom, raising=True)

    # Act
    dl.log(payload)

    # Assert: a record is emitted; no truncation placeholder; original set representation is present
    assert len(h.messages) == 1
    msg = h.messages[0]
    assert "_truncated" not in msg
    assert "{1, 2, 3}" in msg
