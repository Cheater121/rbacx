
import json, os, tempfile, time
from rbacx.policy.loader import FilePolicySource, ReloadingPolicyManager
from rbacx.core.engine import Guard
from rbacx.core.model import Subject, Resource, Action, Context

def test_policy_reload(tmp_path):
    p = tmp_path / "policy.json"
    p.write_text(json.dumps({"rules":[{"id":"d","effect":"deny","actions":["read"],"resource":{"type":"doc"}}]}), encoding='utf-8')
    guard = Guard(json.loads(p.read_text(encoding='utf-8')))

    src = FilePolicySource(str(p))
    mgr = ReloadingPolicyManager(src, guard)

    # initial deny
    d1 = guard.evaluate_sync(Subject(id="u"), Action("read"), Resource(type="doc"), Context())
    assert d1.allowed is False

    # update policy to permit
    p.write_text(json.dumps({"rules":[{"id":"p","effect":"permit","actions":["read"],"resource":{"type":"doc"}}]}), encoding='utf-8')
    # explicit refresh
    changed = mgr.refresh_if_needed()
    assert changed is True
    d2 = guard.evaluate_sync(Subject(id="u"), Action("read"), Resource(type="doc"), Context())
    assert d2.allowed is True
