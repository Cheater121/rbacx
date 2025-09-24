import json
import os
import tempfile
import time

from rbacx import Guard, HotReloader
from rbacx.store import FilePolicySource


def _write_json(path: str, data: dict) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f)
        f.flush()
        os.fsync(f.fileno())


def main() -> None:
    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)

    try:
        policy_permit = {
            "rules": [
                {"id": "r1", "effect": "permit", "actions": ["read"], "resource": {"type": "doc"}}
            ]
        }
        policy_deny = {
            "rules": [
                {"id": "r2", "effect": "deny", "actions": ["read"], "resource": {"type": "doc"}}
            ]
        }

        guard = Guard(policy=policy_permit)

        _write_json(path, policy_permit)

        mgr = HotReloader(guard, FilePolicySource(path))

        print(
            "first:",
            guard.evaluate_sync(
                subject=type("S", (), {"id": "u", "roles": [], "attrs": {}})(),
                action=type("A", (), {"name": "read"})(),
                resource=type("R", (), {"type": "doc", "id": "1", "attrs": {}})(),
                context=type("C", (), {"attrs": {}})(),
            ).effect,
        )

        _write_json(path, policy_deny)
        time.sleep(0.15)
        mgr.poll_once()

        print(
            "after:",
            guard.evaluate_sync(
                subject=type("S", (), {"id": "u", "roles": [], "attrs": {}})(),
                action=type("A", (), {"name": "read"})(),
                resource=type("R", (), {"type": "doc", "id": "1", "attrs": {}})(),
                context=type("C", (), {"attrs": {}})(),
            ).effect,
        )
    finally:
        try:
            os.remove(path)
        except PermissionError:
            pass


if __name__ == "__main__":
    main()
