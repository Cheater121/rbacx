import logging

from rbacx import Action, Context, Guard, Resource, Subject
from rbacx.rebac.local import (
    ComputedUserset,
    InMemoryRelationshipStore,
    LocalRelationshipChecker,
    This,
    TupleToUserset,
)

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


def build_rules():
    """
    Userset-rewrite по типам.
    - В документе/клипе viewer включает:
        * прямой доступ (This)
        * эскалацию от editor (ComputedUserset("editor"))
        * наследование по иерархии parent -> viewer (TupleToUserset("parent", "viewer"))
        * шаринг через группы: resource --granted--> group, а дальше проверяется group.member
          (TupleToUserset("granted", "member"))
    - editor включает This + наследование + эскалацию от owner.
    - owner — только This.
    """
    return {
        "clip": {
            "viewer": [
                This(),
                ComputedUserset("editor"),
                TupleToUserset("parent", "viewer"),
                TupleToUserset("granted", "member"),
            ],
            "editor": [This(), ComputedUserset("owner"), TupleToUserset("parent", "editor")],
            "owner": [This()],
        },
        "camera": {
            "viewer": [
                This(),
                ComputedUserset("editor"),
                TupleToUserset("parent", "viewer"),
                TupleToUserset("granted", "member"),
            ],
            "editor": [This(), ComputedUserset("owner"), TupleToUserset("parent", "editor")],
            "owner": [This()],
        },
        "site": {
            "viewer": [This(), ComputedUserset("editor")],
            "editor": [This(), ComputedUserset("owner")],
            "owner": [This()],
        },
        "group": {
            # group.member проверяется для (user, "member", "group:<id>")
            "member": [This()],
        },
    }


def build_local_checker() -> LocalRelationshipChecker:
    store = InMemoryRelationshipStore()

    # --- Группы и членство ---
    # user:alice состоит в группе ops
    store.add("user:alice", "member", "group:ops")
    # user:carol пока ни в каких группах; user:bob тоже

    # --- Иерархия ---
    # clip:clip1 принадлежит камере camera:cam1
    store.add("camera:cam1", "parent", "clip:clip1")
    # camera:cam1 принадлежит сайту site:HQ
    store.add("site:HQ", "parent", "camera:cam1")

    # --- Доступы на узлах и шаринг ---
    # 1) Наследование сверху: Carol — viewer на всём сайте HQ → унаследует доступ к камере и клипу
    store.add("user:carol", "viewer", "site:HQ")

    # 2) Шаринг клипа для группы ops: clip1 ->granted-> group:ops
    store.add("group:ops", "granted", "clip:clip1")

    # 3) Прямые роли (покажем эскалацию editor→viewer): Dave — editor на камере
    store.add("user:dave", "editor", "camera:cam1")

    # в build_local_checker() рядом с другими add(...)
    store.add("camera:cam1", "parent", "clip:clip2")

    rules = build_rules()
    return LocalRelationshipChecker(store, rules=rules, caveat_registry={})


def build_policy() -> dict:
    # Политика из двух правил:
    # A) Читать клип может любой viewer (по графу)
    # B) Скачивать клип можно, если:
    #    - viewer по графу И
    #    - (клип не PII) ИЛИ (есть MFA)
    return {
        "algorithm": "deny-overrides",
        "rules": [
            {
                "id": "clip-read-if-viewer",
                "effect": "permit",
                "actions": ["clip.read"],
                "resource": {"type": "clip"},
                "condition": {"rel": "viewer"},
            },
            {
                "id": "clip-download-if-viewer-and-safe",
                "effect": "permit",
                "actions": ["clip.download"],
                "resource": {"type": "clip"},
                "condition": {
                    "and": [
                        {"rel": "viewer"},
                        {
                            "or": [
                                {"!=": [{"attr": "resource.attrs.sensitivity"}, "pii"]},
                                {"==": [{"attr": "context.mfa"}, True]},
                            ]
                        },
                    ]
                },
                "obligations": [
                    # пример обязательств: если всё же deny из-за MFA, можно подсказать челлендж
                    {"on": "deny", "type": "require_mfa"}
                ],
            },
        ],
    }


def run():
    checker = build_local_checker()
    policy = build_policy()
    guard = Guard(policy=policy, relationship_checker=checker)

    read = Action(name="clip.read")
    download = Action(name="clip.download")
    clip1 = Resource(type="clip", id="clip1", attrs={"sensitivity": "pii"})  # PII-клип
    clip2 = Resource(type="clip", id="clip2", attrs={"sensitivity": "public"})  # для контраста

    # CASE 1: Alice читает PII-клип — разрешено через group grant (clip1 -> group:ops, alice member ops)
    alice = Subject(id="alice", roles=[], attrs={})
    print("CASE 1: alice -> clip.read clip1")
    print(guard.is_allowed_sync(alice, read, clip1, Context(attrs={})))

    # CASE 2: Alice скачивает PII-клип без MFA — запрет
    print("CASE 2: alice -> clip.download clip1 (no MFA)")
    print(guard.is_allowed_sync(alice, download, clip1, Context(attrs={})))

    # CASE 3: Alice скачивает PII-клип с MFA — разрешено
    print("CASE 3: alice -> clip.download clip1 (with MFA)")
    print(guard.is_allowed_sync(alice, download, clip1, Context(attrs={"mfa": True})))

    # CASE 4: Bob читает клип — нет членства и нет наследования → запрет
    bob = Subject(id="bob", roles=[], attrs={})
    print("CASE 4: bob -> clip.read clip1")
    print(guard.is_allowed_sync(bob, read, clip1, Context(attrs={})))

    # CASE 5: Carol читает клип — viewer на сайте наследуется вниз → разрешено
    carol = Subject(id="carol", roles=[], attrs={})
    print("CASE 5: carol -> clip.read clip1 (site viewer -> inherited)")
    print(guard.is_allowed_sync(carol, read, clip1, Context(attrs={})))

    # CASE 6: Dave читает/скачивает клип — editor на камере эскалируется в viewer на клипе -> разрешено
    dave = Subject(id="dave", roles=[], attrs={})
    print("CASE 6.1: dave -> clip.read clip1 (editor on camera -> viewer on clip)")
    print(guard.is_allowed_sync(dave, read, clip1, Context(attrs={})))
    print("CASE 6.2: dave -> clip.download clip2 (public clip)")
    print(guard.is_allowed_sync(dave, download, clip2, Context(attrs={})))


if __name__ == "__main__":
    run()
