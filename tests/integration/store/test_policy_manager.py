import time

from rbacx.policy.loader import HotReloader


class Src:
    def __init__(self):
        self._etag = "1"
        self.loads = 0

    def etag(self):
        return self._etag

    def load(self):
        self.loads += 1
        return {"rules": []}

    def set(self, etag):
        self._etag = etag


class Guard:
    def __init__(self):
        self.sets = 0

    def set_policy(self, p):
        self.sets += 1


def test_hot_reloader_check_and_threading():
    src = Src()
    g = Guard()
    rld = HotReloader(g, src, initial_load=True, poll_interval=0.001)
    # initial load forced
    changed = rld.check_and_reload(force=True)
    assert changed is True
    # second time same etag -> no
    changed = rld.check_and_reload()
    assert changed is False
    # start/stop thread quickly
    rld.start(interval=0.001, initial_load=False)
    time.sleep(0.01)
    rld.stop()
