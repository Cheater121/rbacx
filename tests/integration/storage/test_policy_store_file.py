
import json, tempfile, os
from rbacx.store.file_store import FilePolicySource
from rbacx.store.manager import PolicyManager
from rbacx.core.engine import Guard

def test_file_policy_source_load_and_manager_update():
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "policy.json")
        json.dump({"rules":[{"id":"p","effect":"permit","actions":["read"],"resource":{"type":"doc"}}]}, open(p, "w"))
        src = FilePolicySource(p)
        guard = Guard(policy={})
        mgr = PolicyManager(guard, src)
        changed = mgr.poll_once()
        assert changed
        from rbacx.core.model import Subject, Resource, Action, Context
        d1 = guard.evaluate_sync(Subject(id="u"), Action("read"), Resource(type="doc"), Context())
        assert d1.allowed is True
