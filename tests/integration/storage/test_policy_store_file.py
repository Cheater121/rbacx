import json
import os
import tempfile

from rbacx.core.engine import Guard
from rbacx.policy.loader import HotReloader
from rbacx.store.file_store import FilePolicySource


def test_file_policy_source_load_and_manager_update():
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "policy.json")
        json.dump(
            {
                "rules": [
                    {
                        "id": "p",
                        "effect": "permit",
                        "actions": ["read"],
                        "resource": {"type": "doc"},
                    }
                ]
            },
            open(p, "w"),
        )
        src = FilePolicySource(p)
        guard = Guard(policy={})
        rld = HotReloader(guard, src, initial_load=True)
        changed = rld.check_and_reload(force=True)
        assert changed
        from rbacx.core.model import Action, Context, Resource, Subject

        d1 = guard.evaluate_sync(Subject(id="u"), Action("read"), Resource(type="doc"), Context())
        assert d1.allowed is True
