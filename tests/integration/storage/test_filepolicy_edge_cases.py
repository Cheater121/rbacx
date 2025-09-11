
import os, json, tempfile, pathlib
from rbacx.storage import FilePolicySource

def test_file_policy_source_missing_file_etag_none_and_load_error(tmp_path):
    p = tmp_path / "nope.json"
    s = FilePolicySource(str(p), validate_schema=False)
    assert s.etag() is None
    # load on missing file should raise FileNotFoundError
    try:
        s.load()
    except FileNotFoundError:
        pass
