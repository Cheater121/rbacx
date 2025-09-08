from datetime import datetime, timedelta, timezone
from rbacx.core.engine import Guard
from rbacx.core.model import Subject, Action, Resource, Context

def main() -> None:
    now = datetime.now(timezone.utc)
    policy = {"rules":[
        {"id":"within", "effect":"permit", "actions":["read"], "resource":{"type":"doc"},
         "condition":{"between":[ {"attr":"context.attrs.when"}, [now.isoformat(), (now + timedelta(hours=1)).isoformat()] ]}},
    ]}
    g = Guard(policy)
    d = g.evaluate_sync(
        subject=Subject(id="u"),
        action=Action("read"),
        resource=Resource(type="doc"),
        context=Context(attrs={"when": now.isoformat()}),
    )
    print(d.allowed, d.reason)  # True, matched

if __name__ == "__main__":
    main()
