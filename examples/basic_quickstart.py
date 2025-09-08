from rbacx.core.engine import Guard
from rbacx.core.model import Subject, Action, Resource, Context

def main() -> None:
    policy = {
        "algorithm": "deny-overrides",
        "rules": [
            {
                "id": "doc_read",
                "effect": "permit",
                "actions": ["read"],
                "resource": {"type": "doc"},
                "condition": {"hasAny": [ {"attr": "subject.roles"}, ["reader", "admin"] ]},
            },
            {"id": "deny_archived", "effect": "deny", "actions": ["*"], "resource": {"type": "doc", "attrs": {"archived": True}}},
        ],
    }
    g = Guard(policy)
    d = g.evaluate_sync(
        subject=Subject(id="u1", roles=["reader"]),
        action=Action("read"),
        resource=Resource(type="doc", id="42", attrs={"archived": False}),
        context=Context(attrs={}),
    )
    print(d.allowed, d.reason)  # True, "matched"

if __name__ == "__main__":
    main()
