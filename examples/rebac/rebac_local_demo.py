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


def build_local_checker() -> LocalRelationshipChecker:
    # --- 1) tuples (relationship facts) ---
    store = InMemoryRelationshipStore()

    # Direct membership: Alice is a viewer of folder:root
    store.add("user:alice", "viewer", "folder:root")

    # Object->object edge: document:doc1 has parent folder:root
    # (i.e., traverse 'parent' from doc -> folder)
    store.add("folder:root", "parent", "document:doc1")

    # NB: Bob has no relationships -> should be denied

    # --- 2) userset rewrite rules (per object type) ---
    # Semantics:
    # - document.viewer: union of direct 'viewer', inherited via 'parent'→'viewer',
    #   and escalation from 'editor' (editors can view).
    # - document.editor: direct 'editor'.
    # - folder.viewer: direct 'viewer'.
    rules = {
        "document": {
            "viewer": [This(), ComputedUserset("editor"), TupleToUserset("parent", "viewer")],
            "editor": [This()],
        },
        "folder": {
            "viewer": [This()],
        },
    }

    # Optional caveats registry (empty for this demo)
    caveats = {}

    return LocalRelationshipChecker(store, rules=rules, caveat_registry=caveats)


def build_policy() -> dict:
    # "Правдоподобная" политика: читать документ может тот, кто состоит
    # в отношении 'viewer' к ресурсу (через ReBAC-граф).
    return {
        "algorithm": "deny-overrides",
        "rules": [
            {
                "id": "doc-read-if-viewer",
                "effect": "permit",
                "actions": ["document.read"],
                "resource": {"type": "document"},
                # rel как строка: subject и resource берутся из env
                "condition": {"rel": "viewer"},
            }
        ],
    }


def main() -> None:
    checker = build_local_checker()
    policy = build_policy()

    guard = Guard(policy=policy, relationship_checker=checker)

    # --------- CASE 1: PERMIT (alice can read doc1 via folder inheritance) ----------
    alice = Subject(id="alice", roles=[], attrs={})
    read = Action(name="document.read")
    doc1 = Resource(type="document", id="doc1", attrs={})
    ctx = Context(attrs={})

    decision1 = guard.evaluate_sync(alice, read, doc1, ctx)
    print("CASE 1: alice -> document.read doc1")
    print(
        "  allowed =",
        decision1.allowed,
        "| effect =",
        decision1.effect,
        "| rule_id =",
        decision1.rule_id,
    )
    print()

    # --------- CASE 2: DENY (bob has no relation granting view) ----------
    bob = Subject(id="bob", roles=[], attrs={})
    decision2 = guard.evaluate_sync(bob, read, doc1, ctx)
    print("CASE 2: bob -> document.read doc1")
    print(
        "  allowed =",
        decision2.allowed,
        "| effect =",
        decision2.effect,
        "| reason =",
        decision2.reason,
    )
    print()


if __name__ == "__main__":
    main()
