
import sys, types
from rbacx.telemetry.decision_log import StdoutDecisionLogger

def test_stdout_logger_handles_write_error(monkeypatch):
    def boom(_): raise RuntimeError("io")
    class _Stdout: pass
    fake = _Stdout()
    fake.write = boom
    monkeypatch.setattr(sys, "stdout", fake, raising=True)
    l = StdoutDecisionLogger()
    # Should not raise
    l.log({"a": 1})
