# Authorization Strategies: RBAC, ABAC, ReBAC

There are the three strategies supported by RBACX.

## RBAC (Role-Based Access Control)

* **Concept.** Users are assigned roles; roles grant permissions.
* **Use when.** Stable, bounded sets of duties (e.g., back-office roles).

## ABAC (Attribute-Based Access Control)

* **Concept.** Policies evaluate attributes of subject, resource, action, and environment.
* **Use when.** Dynamic, fine-grained rules (ownership, time, location, device posture).

## ReBAC (Relationship-Based Access Control)

* **Concept.** Permissions derive from relationships between subjects and resources (Zanzibar-style).
* **Use when.** Collaboration graphs, sharing models, delegation, inheritance chains.
* See `docs/rebac/*` for detailed guides.
