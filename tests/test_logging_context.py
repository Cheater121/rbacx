
import logging
from rbacx.logging.context import set_current_trace_id, get_current_trace_id, clear_current_trace_id, gen_trace_id, TraceIdFilter

def test_trace_id_set_get_clear_with_token():
    token = set_current_trace_id("abc")
    assert get_current_trace_id() == "abc"
    clear_current_trace_id(token)
    assert get_current_trace_id() is None

def test_trace_id_clear_without_token():
    set_current_trace_id("xyz")
    clear_current_trace_id()
    assert get_current_trace_id() is None

def test_gen_trace_id_is_uuid_like_and_filter_injects_record_field(caplog):
    rid = gen_trace_id()
    assert isinstance(rid, str) and len(rid) >= 32
    logger = logging.getLogger("rbacx.test")
    logger.setLevel(logging.INFO)
    caplog.set_level(logging.INFO, logger="rbacx.test")
    f = TraceIdFilter()
    logger.addFilter(f)
    set_current_trace_id("trace-1")
    try:
        logger.info("msg")
        assert caplog.records
        rec = caplog.records[-1]
        assert hasattr(rec, "trace_id")
        assert rec.trace_id == "trace-1"
    finally:
        clear_current_trace_id()
        logger.removeFilter(f)
