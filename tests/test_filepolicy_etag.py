
import json, time, os
from rbacx.storage import FilePolicySource, HotReloader
from rbacx.core.engine import Guard

def test_filepolicy_etag_changes(tmp_path):
    p = tmp_path / "p.json"
    p.write_text(json.dumps({"rules":[{"id":"r","effect":"permit","actions":["read"],"resource":{"type":"doc"}}]}), encoding="utf-8")
    src = FilePolicySource(str(p))
    g = Guard(json.loads(p.read_text(encoding="utf-8")))
    rl = HotReloader(g, src, poll_interval=0.0)
    first = src.etag()
    assert rl.check_and_reload() is False  # nothing changed
    # update file
    p.write_text(json.dumps({"rules":[{"id":"r2","effect":"permit","actions":["read"],"resource":{"type":"doc"}}]}), encoding="utf-8")
    assert rl.check_and_reload() is True
    assert src.etag() != first
