import json
import logging

from rbacx.logging.decision_logger import DecisionLogger


def test_decision_logger_as_json_true_emits_json(caplog):
    caplog.set_level(logging.INFO, logger="rbacx.audit")
    logger = DecisionLogger(as_json=True, level=logging.INFO)
    payload = {"decision": "allow", "env": {"k": "v"}}

    logger.log(payload)

    assert caplog.records, "No log records captured"
    rec = caplog.records[-1]
    # Message must be JSON-serialized payload
    assert rec.getMessage() == json.dumps(payload, ensure_ascii=False)
    assert rec.levelno == logging.INFO
    assert rec.name == "rbacx.audit"


def test_decision_logger_as_json_false_emits_text_prefix(caplog):
    caplog.set_level(logging.DEBUG, logger="rbacx.audit")
    logger = DecisionLogger(as_json=False, level=logging.DEBUG)
    payload = {"decision": "allow", "env": {"x": 1}}

    logger.log(payload)

    assert caplog.records, "No log records captured"
    rec = caplog.records[-1]
    msg = rec.getMessage()
    # Expect textual prefix and python-dict representation
    assert msg.startswith("decision {")
    assert "'decision': 'allow'" in msg
    assert "'env': {'x': 1}" in msg
    assert rec.levelno == logging.DEBUG
    assert rec.name == "rbacx.audit"


def test_decision_logger_respects_log_level_warning(caplog):
    caplog.set_level(logging.INFO, logger="rbacx.audit")
    logger = DecisionLogger(as_json=True, level=logging.WARNING)

    logger.log({"decision": "deny"})

    assert caplog.records, "No log records captured"
    rec = caplog.records[-1]
    assert rec.levelno == logging.WARNING


def test_decision_logger_sampling_zero_emits_nothing(caplog):
    caplog.set_level(logging.INFO, logger="rbacx.audit")
    logger = DecisionLogger(sample_rate=0.0, as_json=True, level=logging.INFO)

    logger.log({"decision": "allow"})
    logger.log({"decision": "deny"})

    # With sample_rate=0.0 nothing should be logged
    assert not caplog.records
