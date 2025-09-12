import json
import os
import tempfile
import time

from rbacx.core.engine import Guard
from rbacx.policy.loader import HotReloader
from rbacx.storage import FilePolicySource


def main() -> None:
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
    try:
        # initial policy
        json.dump(
            {
                "rules": [
                    {
                        "id": "r1",
                        "effect": "permit",
                        "actions": ["read"],
                        "resource": {"type": "doc"},
                    }
                ]
            },
            open(tmp.name, "w"),
        )
        guard = Guard(policy={})
        mgr = HotReloader(guard, FilePolicySource(tmp.name))
        mgr.poll_once()
        print(
            "first:",
            guard.evaluate_sync(
                subject=type("S", (), {"id": "u", "roles": [], "attrs": {}})(),
                action=type("A", (), {"name": "read"})(),
                resource=type("R", (), {"type": "doc", "id": "1", "attrs": {}})(),
                context=type("C", (), {"attrs": {}})(),
            ).decision,
        )

        # update policy
        time.sleep(0.1)
        json.dump(
            {
                "rules": [
                    {
                        "id": "deny",
                        "effect": "deny",
                        "actions": ["read"],
                        "resource": {"type": "doc"},
                    }
                ]
            },
            open(tmp.name, "w"),
        )
        mgr.poll_once()
        print(
            "after:",
            guard.evaluate_sync(
                subject=type("S", (), {"id": "u", "roles": [], "attrs": {}})(),
                action=type("A", (), {"name": "read"})(),
                resource=type("R", (), {"type": "doc", "id": "1", "attrs": {}})(),
                context=type("C", (), {"attrs": {}})(),
            ).decision,
        )
    finally:
        os.unlink(tmp.name)


if __name__ == "__main__":
    main()
