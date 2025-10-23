"""
Demo: RBACX + OpenFGA (ReBAC)
Run after starting the local OpenFGA docker compose and importing model/tuples.
Requires environment variable:
  OPENFGA_STORE_ID=<store id printed by `fga store list`>
Optional:
  OPENFGA_MODEL_ID=<authorization_model_id>  # to pin a specific model
"""

import os
import sys

from rbacx import Action, Context, Guard, Resource, Subject
from rbacx.rebac.openfga import OpenFGAChecker, OpenFGAConfig

STORE_ID = os.getenv("OPENFGA_STORE_ID")
MODEL_ID = os.getenv("OPENFGA_MODEL_ID")  # optional

if not STORE_ID:
    print("Please set OPENFGA_STORE_ID (use `fga store list` to get it).", file=sys.stderr)
    sys.exit(2)

policy = {
    "algorithm": "deny-overrides",
    "rules": [
        {
            "id": "clip-viewer-via-openfga",
            "effect": "permit",
            "actions": ["clip.read"],
            "resource": {"type": "clip"},
            # default: subject=user:{env.subject.id}, resource=clip:{env.resource.id}
            "condition": {"rel": {"relation": "viewer"}},
        }
    ],
}

checker = OpenFGAChecker(
    OpenFGAConfig(
        api_url="http://localhost:8080",
        store_id=STORE_ID,
        authorization_model_id=MODEL_ID,  # may be None -> latest
        timeout_seconds=2.0,
    )
)

guard = Guard(policy=policy, relationship_checker=checker)

# Example: alice reads clip1
decision = guard.evaluate_sync(
    Subject(id="alice", roles=[], attrs={}),
    Action(name="clip.read"),
    Resource(type="clip", id="clip1", attrs={}),
    Context(attrs={}),
)

print("Allowed:", decision.allowed)
if not decision.allowed:
    print("Reason:", decision.reason, "Rule:", decision.rule_id)
