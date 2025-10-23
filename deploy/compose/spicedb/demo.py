from rbacx import Action, Context, Guard, Resource, Subject
from rbacx.rebac.spicedb import SpiceDBChecker, SpiceDBConfig

policy = {
    "algorithm": "deny-overrides",
    "rules": [
        {
            "id": "clip-read-via-rebac",
            "effect": "permit",
            "actions": ["clip.read"],
            "resource": {"type": "clip"},
            "condition": {"rel": {"relation": "read"}},
        }
    ],
}

checker = SpiceDBChecker(
    SpiceDBConfig(endpoint="localhost:50051", token="rbacx-dev-secret", insecure=True)
)
guard = Guard(policy=policy, relationship_checker=checker)

d = guard.evaluate_sync(
    Subject(id="alice", roles=[], attrs={}),
    Action(name="clip.read"),
    Resource(type="clip", id="clip1", attrs={}),
    Context(attrs={}),
)
print(d.allowed)
