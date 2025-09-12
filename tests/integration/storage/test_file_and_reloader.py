# tests/integration/storage/test_file_and_reloader.py
import json
import os
import sys
import time
import types

from rbacx.core.engine import Guard
from rbacx.storage import FilePolicySource, HotReloader, atomic_write


def test_atomic_write_and_content_etag_changes(tmp_path):
    path = tmp_path / "a.json"
    atomic_write(str(path), data='{"a":1}', encoding="utf-8")
    assert json.loads(path.read_text(encoding="utf-8")) == {"a": 1}

    src = FilePolicySource(str(path), validate_schema=False)
    et1 = src.etag()

    # Change content AND length to avoid depending on FS timestamp granularity
    atomic_write(str(path), data='{"a":2,"pad":0}', encoding="utf-8")
    et2 = src.etag()
    assert et1 != et2


def test_include_mtime_in_etag_allows_touch_trigger(tmp_path):
    path = tmp_path / "p.json"
    atomic_write(str(path), data='{"rules": []}', encoding="utf-8")

    # Default: content-only ETag
    src_default = FilePolicySource(str(path))
    et_default_1 = src_default.etag()

    # With mtime in ETag
    src_mtime = FilePolicySource(str(path), include_mtime_in_etag=True)
    et_mtime_1 = src_mtime.etag()

    # Force mtime to advance even on coarse timestamp filesystems
    st = os.stat(str(path))
    new_mtime = max(st.st_mtime, time.time()) + 2
    os.utime(str(path), (st.st_atime, new_mtime))

    # Default ETag should remain the same (content unchanged)
    assert src_default.etag() == et_default_1
    # mtime-based ETag should change
    assert src_mtime.etag() != et_mtime_1


def test_filepolicy_caching_skips_rehash_when_metadata_unchanged(tmp_path, monkeypatch):
    path = tmp_path / "cache.json"
    atomic_write(str(path), data='{"v":1}', encoding="utf-8")
    src = FilePolicySource(str(path))

    calls = {"n": 0}
    orig_hash = src._hash_file

    def spy_hash():
        calls["n"] += 1
        return orig_hash()

    monkeypatch.setattr(src, "_hash_file", spy_hash)
    # First etag() computes hash
    _ = src.etag()
    # Second etag() with no metadata change must not hash again
    _ = src.etag()
    assert calls["n"] == 1

    # Touch mtime only -> metadata changes -> hash recomputed (etag same)
    st = os.stat(str(path))
    os.utime(str(path), (st.st_atime, st.st_mtime + 1))
    _ = src.etag()
    assert calls["n"] == 2


def test_filepolicy_validate_schema_called(tmp_path):
    path = tmp_path / "schema.json"
    atomic_write(str(path), data='{"ok": true}', encoding="utf-8")

    # Inject a fake validator module
    mod = types.ModuleType("rbacx.dsl.validate")
    flag = {"called": False}

    def validate_policy(policy):
        flag["called"] = True

    mod.validate_policy = validate_policy  # type: ignore[attr-defined]
    sys.modules["rbacx.dsl.validate"] = mod

    src = FilePolicySource(str(path), validate_schema=True)
    _ = src.load()
    assert flag["called"] is True


def test_hot_reloader_detects_change_and_applies_policy(tmp_path):
    path = tmp_path / "policy.json"
    atomic_write(
        str(path),
        data=json.dumps({"rules": [{"id": "r1", "effect": "permit"}]}),
        encoding="utf-8",
    )

    src = FilePolicySource(str(path))
    guard = Guard(json.loads(path.read_text(encoding="utf-8")))
    rld = HotReloader(guard, src, poll_interval=0.01)

    # First check: no change since HotReloader initialized with current etag
    assert rld.check_and_reload() is False

    # Update policy content (and length) so metadata changes for sure
    atomic_write(
        str(path),
        data=json.dumps({"rules": [{"id": "r2", "effect": "deny"}, {"x": 1}]}),
        encoding="utf-8",
    )

    # Next check should reload and apply
    assert rld.check_and_reload() is True
    assert guard.policy.get("rules", [{}])[0].get("id") == "r2"


def test_hot_reloader_background_loop_start_stop(tmp_path):
    path = tmp_path / "bg.json"
    atomic_write(str(path), data=json.dumps({"rules": [{"id": "r0"}]}), encoding="utf-8")

    src = FilePolicySource(str(path))
    guard = Guard(json.loads(path.read_text(encoding="utf-8")))
    rld = HotReloader(guard, src, poll_interval=0.05)
    rld.start()
    try:
        # Change content and wait for the background thread to pick it up
        atomic_write(str(path), data=json.dumps({"rules": [{"id": "r_bg"}]}), encoding="utf-8")
        deadline = time.time() + 2.0
        while time.time() < deadline and guard.policy.get("rules", [{}])[0].get("id") != "r_bg":
            time.sleep(0.05)
        assert guard.policy.get("rules", [{}])[0].get("id") == "r_bg"
    finally:
        rld.stop()


def test_hot_reloader_error_suppression_sets_window(tmp_path):
    class BadSource:
        def etag(self):
            # Return None so HotReloader attempts load() and hits the JSON error path.
            return None

        def load(self):
            # Simulate invalid JSON (HotReloader catches json.JSONDecodeError)
            raise json.JSONDecodeError("bad", "doc", 0)

        path = "<bad>"

    guard = Guard({"rules": []})
    rld = HotReloader(guard, BadSource(), poll_interval=0.01)
    assert rld.check_and_reload() is False
    assert rld.suppressed_until > time.time()
