import json
import logging

from rbacx.logging.decision_logger import DecisionLogger


class DummyLogger:
    def __init__(self):
        self.records = []

    def log(self, level, msg):
        self.records.append((level, msg))


def test_decision_logger_json_and_sampling(monkeypatch):
    dl = DecisionLogger(sample_rate=1.0, level=logging.INFO, as_json=True)
    # inject dummy logger
    dl.logger = DummyLogger()

    # Force sampling hit
    monkeypatch.setattr("random.random", lambda: 0.0, raising=False)
    dl.log({"env": {"user": "u"}, "decision": "permit", "allowed": True})
    assert dl.logger.records and isinstance(json.loads(dl.logger.records[-1][1]), dict)


def test_decision_logger_redactions_and_exception_fallback(monkeypatch):
    dl = DecisionLogger(
        sample_rate=1.0, level=logging.INFO, as_json=False, redactions=[{"remove": ["secret"]}]
    )
    dl.logger = DummyLogger()

    # Make apply_obligations raise to hit except path
    monkeypatch.setattr(
        "rbacx.logging.decision_logger.apply_obligations",
        lambda env, r: (_ for _ in ()).throw(RuntimeError("boom")),
        raising=True,
    )
    dl.log({"env": {"secret": "s"}, "decision": "deny", "allowed": False})
    # Should still log a string message despite redaction failure
    assert dl.logger.records and isinstance(dl.logger.records[-1][1], str)
