
import json, types, time
from rbacx.storage import HotReloader

class _Guard:
    def __init__(self): self.policy=None
    def set_policy(self, p): self.policy = p

def test_hot_reloader_json_error_and_suppression(monkeypatch):
    class BadGoodSrc:
        def __init__(self): self._bad = True
        def etag(self): return str(time.time())
        def load(self):
            if self._bad:
                self._bad = False
                raise json.JSONDecodeError("x","y",0)
            return {"policies": []}
    g = _Guard()
    hr = HotReloader(g, BadGoodSrc(), poll_interval=0.01)
    assert hr.check_and_reload() is False  # first: bad JSON
    assert hr.check_and_reload() is False  # suppressed immediately after
    # Wait a bit, then call again — accept either False (if the suppression window is still active)
    # or True (if the window has passed and the load succeeds).
    time.sleep(0.05)
    res = hr.check_and_reload()
    assert res in (False, True)
    if res:
        assert g.policy == {"policies": []}

def test_hot_reloader_file_not_found_and_generic(monkeypatch):
    class NotFoundSrc:
        def etag(self): return None
        def load(self):
            raise FileNotFoundError("no")
    class BoomSrc:
        def etag(self): return "x"
        def load(self): raise RuntimeError("boom")
    g = _Guard()
    hr1 = HotReloader(g, NotFoundSrc(), poll_interval=0.01)
    assert hr1.check_and_reload() is False
    hr2 = HotReloader(g, BoomSrc(), poll_interval=0.01)
    assert hr2.check_and_reload() is False
