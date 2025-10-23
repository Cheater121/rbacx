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
    Userset-rewrite by type.
    - In a document/clip, viewer includes:
        * direct access (This)
        * escalation from editor (ComputedUserset("editor"))
        * inheritance via hierarchy parent -> viewer (TupleToUserset("parent", "viewer"))
        * sharing through groups: resource --granted--> group, then group.member is checked
          (TupleToUserset("granted", "member"))
    - editor includes This + inheritance + escalation from owner.
    - owner — only This.
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
            # group.member is checked for (user, "member", "group:<id>")
            "member": [This()],
        },
    }


def build_local_checker() -> LocalRelationshipChecker:
    store = InMemoryRelationshipStore()

    # --- Groups and membership ---
    # user:alice is a member of the group ops
    store.add("user:alice", "member", "group:ops")
    # user:carol is not in any groups yet; user:bob as well

    # --- Hierarchy ---
    # clip:clip1 belongs to camera:cam1
    store.add("camera:cam1", "parent", "clip:clip1")
    # camera:cam1 belongs to site:HQ
    store.add("site:HQ", "parent", "camera:cam1")

    # --- Access rights and sharing ---
    # 1) Inheritance from above: Carol is a viewer of the entire HQ site → inherits access to camera and clip
    store.add("user:carol", "viewer", "site:HQ")

    # 2) Sharing clip with group ops: clip1 ->granted-> group:ops
    store.add("group:ops", "granted", "clip:clip1")

    # 3) Direct roles (demonstrating editor→viewer escalation): Dave is an editor on the camera
    store.add("user:dave", "editor", "camera:cam1")

    # additional clip for demonstration
    store.add("camera:cam1", "parent", "clip:clip2")

    rules = build_rules()
    return LocalRelationshipChecker(store, rules=rules, caveat_registry={})


def build_policy() -> dict:
    # Policy with two rules:
    # A) Any viewer (according to the graph) can read a clip
    # B) Clip can be downloaded if:
    #    - viewer according to the graph AND
    #    - (clip is not PII) OR (MFA is enabled)
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
                    # Example of an obligation: if denied due to MFA, a challenge can be suggested
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
    clip1 = Resource(type="clip", id="clip1", attrs={"sensitivity": "pii"})  # PII clip
    clip2 = Resource(type="clip", id="clip2", attrs={"sensitivity": "public"})  # for contrast

    # CASE 1: Alice reads PII clip — allowed through group grant (clip1 -> group:ops, alice member of ops)
    alice = Subject(id="alice", roles=[], attrs={})
    print("CASE 1: alice -> clip.read clip1")
    print(guard.is_allowed_sync(alice, read, clip1, Context(attrs={})))

    # CASE 2: Alice downloads PII clip without MFA — denied
    print("CASE 2: alice -> clip.download clip1 (no MFA)")
    print(guard.is_allowed_sync(alice, download, clip1, Context(attrs={})))

    # CASE 3: Alice downloads PII clip with MFA — allowed
    print("CASE 3: alice -> clip.download clip1 (with MFA)")
    print(guard.is_allowed_sync(alice, download, clip1, Context(attrs={"mfa": True})))

    # CASE 4: Bob reads clip — no membership and no inheritance → denied
    bob = Subject(id="bob", roles=[], attrs={})
    print("CASE 4: bob -> clip.read clip1")
    print(guard.is_allowed_sync(bob, read, clip1, Context(attrs={})))

    # CASE 5: Carol reads clip — viewer on site is inherited downward → allowed
    carol = Subject(id="carol", roles=[], attrs={})
    print("CASE 5: carol -> clip.read clip1 (site viewer -> inherited)")
    print(guard.is_allowed_sync(carol, read, clip1, Context(attrs={})))

    # CASE 6: Dave reads/downloads clip — editor on camera escalates to viewer on clip -> allowed
    dave = Subject(id="dave", roles=[], attrs={})
    print("CASE 6.1: dave -> clip.read clip1 (editor on camera -> viewer on clip)")
    print(guard.is_allowed_sync(dave, read, clip1, Context(attrs={})))
    print("CASE 6.2: dave -> clip.download clip2 (public clip)")
    print(guard.is_allowed_sync(dave, download, clip2, Context(attrs={})))


if __name__ == "__main__":
    run()
