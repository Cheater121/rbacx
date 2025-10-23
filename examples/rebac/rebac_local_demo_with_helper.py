"""
ReBAC (local) demo using helper: rbacx.rebac.helpers.standard_userset

Scenarios covered:
  1) Direct ownership -> viewer via helper chain (owner -> editor -> viewer)
  2) Inherited access from parent folder (TupleToUserset("parent", "..."))
  3) Group grant: document granted to a group, user is group.member

Run:
  python examples/rebac/rebac_helper_local_demo.py
"""

import logging

from rbacx import Action, Context, Guard, Resource, Subject
from rbacx.rebac.helpers import standard_userset
from rbacx.rebac.local import (
    InMemoryRelationshipStore,
    LocalRelationshipChecker,
    This,  # used for simple folder/group rules
)

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


def build_local_checker() -> LocalRelationshipChecker:
    store = InMemoryRelationshipStore()

    # ------------------------
    # Relationship tuples (facts)
    # ------------------------
    # 1) Direct owner for doc1
    store.add("user:alice", "owner", "document:doc1")

    # 2) Parent folder -> document edges (folder:f1 is parent of doc2 and doc3)
    store.add("folder:f1", "parent", "document:doc2")
    store.add("folder:f1", "parent", "document:doc3")

    # Bob is a viewer of folder f1 (inherits viewer on its documents)
    store.add("user:bob", "viewer", "folder:f1")

    # 3) Group grant: doc3 is granted to group g1; Carol is member of g1
    store.add("group:g1", "granted", "document:doc3")
    store.add("user:carol", "member", "group:g1")

    # ------------------------
    # Userset rules via helper
    # ------------------------
    # For "document" we take a standard viewer/editor/owner set:
    # - viewer: This() OR editor OR parent.viewer OR granted.member
    # - editor: This() OR owner
    # - owner : This()
    # parent_rel="parent" enables TupleToUserset("parent", rel) rewrites
    doc_rules = standard_userset(parent_rel="parent", with_group_grants=True)

    # Minimal rules for folder/group to support the above rewrites
    rules = {
        "document": doc_rules,
        "folder": {
            "viewer": [This()],
            "editor": [This()],
            "owner": [This()],
        },
        "group": {
            "member": [This()],
        },
    }

    return LocalRelationshipChecker(
        store,
        rules=rules,
        # Optional safety limits (defaults shown):
        max_depth=8,
        max_nodes=10_000,
        deadline_ms=50,
    )


def build_policy() -> dict:
    # Permit "read" on documents if subject is a "viewer" (via ReBAC)
    return {
        "algorithm": "deny-overrides",
        "rules": [
            {
                "id": "doc_read_if_viewer",
                "effect": "permit",
                "actions": ["read"],
                "resource": {"type": "document"},
                "condition": {"rel": "viewer"},
            }
        ],
    }


def check(guard: Guard, user_id: str, action: str, res_type: str, res_id: str) -> None:
    subj = Subject(id=user_id)
    act = Action(action)
    res = Resource(type=res_type, id=res_id)
    ctx = Context()
    decision = guard.evaluate_sync(subj, act, res, ctx)
    print(
        f"{user_id} -> {action} {res_type}:{res_id} | "
        f"allowed={decision.allowed} effect={decision.effect} reason={decision.reason}"
    )


def main() -> None:
    checker = build_local_checker()
    policy = build_policy()
    guard = Guard(policy, relationship_checker=checker)

    print("\n=== CASE 1: owner chain (owner -> editor -> viewer) ===")
    check(guard, "alice", "read", "document", "doc1")  # Permit via owner chain

    print("\n=== CASE 2: parent folder inheritance ===")
    check(guard, "bob", "read", "document", "doc2")  # Permit via parent: folder.viewer

    print("\n=== CASE 3: group grant (granted -> member) ===")
    check(guard, "carol", "read", "document", "doc3")  # Permit via group grant

    print("\n=== NEGATIVE: unrelated user ===")
    check(guard, "mallory", "read", "document", "doc1")  # Deny


if __name__ == "__main__":
    main()
