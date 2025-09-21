import rbacx.logging.decision_logger as dlmod


# Covers line 62: callable(dbg) -> dbg("DecisionLogger: failed...", exc_info=True)
def test_decision_logger_calls_debug_on_redaction_error(monkeypatch):
    # Force sampling to pass
    monkeypatch.setattr(dlmod.random, "random", lambda: 0.0, raising=True)

    # Make apply_obligations raise to enter the except branch
    def boom(*args, **kwargs):
        raise RuntimeError("redaction failed")

    monkeypatch.setattr(dlmod, "apply_obligations", boom, raising=True)

    # Stub logger capturing debug() calls and accepting log()
    class StubLogger:
        def __init__(self):
            self.debug_calls = []
            self.logged = []

        # We need a callable 'debug' for the branch to execute
        def debug(self, msg, **kwargs):
            self.debug_calls.append((msg, kwargs))

        def log(self, level, msg):
            self.logged.append((level, msg))

    logger = StubLogger()
    dlog = dlmod.DecisionLogger(
        sample_rate=1.0,
        redactions=[{"type": "mask_fields", "fields": ["user.email"]}],
        as_json=True,
    )
    # Inject our stub logger so callable(dbg) is True
    dlog.logger = logger

    # Run
    dlog.log({"env": {"user": {"email": "a@b"}}})

    # Assert that debug() was called with exc_info=True
    assert logger.debug_calls, "debug() was not called"
    msg, kwargs = logger.debug_calls[0]
    assert msg == "DecisionLogger: failed to apply redactions"
    assert kwargs.get("exc_info") is True

    # And the normal emit still happened
    assert logger.logged, "logger.log() was not called"
