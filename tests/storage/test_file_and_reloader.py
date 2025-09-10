
import json
from rbacx.storage import atomic_write, FilePolicySource

def test_atomic_write_and_hot_reloader(tmp_path):
    path = tmp_path / "a.json"
    atomic_write(str(path), data='{"a":1}', encoding="utf-8")
    assert json.loads(path.read_text()) == {"a": 1}

    src = FilePolicySource(str(path), validate_schema=False)
    et1 = src.etag()

    # modify atomically and ensure etag changes
    atomic_write(str(path), data='{"a":2}', encoding="utf-8")
    et2 = src.etag()
    assert et1 != et2
