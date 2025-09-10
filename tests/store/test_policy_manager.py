
import types, time
from rbacx.store.manager import PolicyManager

class Src:
    def __init__(self): self._etag="1"; self.loads=0
    def etag(self): return self._etag
    def load(self): self.loads+=1; return {"rules":[]}

class Guard:
    def __init__(self): self.sets=0
    def set_policy(self, p): self.sets+=1

def test_policy_manager_poll_once_and_threading():
    src=Src(); g=Guard()
    m = PolicyManager(g, src)
    assert m.poll_once() is True
    # second time same etag -> no
    assert m.poll_once() is False
    # start/stop thread quickly
    m.start_polling(0.001)
    time.sleep(0.01)
    m.stop()
