
# Migrating from RBAC to ABAC

This guide outlines pragmatic steps to evolve from role-based access control (RBAC) to attribute-based access control (ABAC).

## 1) Inventory roles & permissions
Export your current RBAC roles and permissions; identify hotspots (over-privileged roles, cross-cutting exceptions).

## 2) Identify key attributes
Subject attributes (department, clearance), resource attributes (owner, tenant, classification), and environmental (time, geo). See NIST SP 800-162 for ABAC components and considerations.

## 3) Start with deny-by-default
Adopt `deny-overrides` and add explicit permits. Keep policies small and typed (resource.type).

## 4) Express exceptions as attributes
Turn ad-hoc role exceptions into ABAC rules (e.g., owner-based access). Prefer small, composable conditions.

## 5) Dual-run with audit-mode
Run PDP in audit mode alongside enforcement; compare `Decision.reason` and logs to detect gaps before enforcing.

## 6) Decompose roles
Gradually replace monolithic roles by attributes; maintain role hierarchy if needed (resolver) while transitioning.

## 7) Validate & lint
Use JSON Schema validation and `rbacx lint` to catch issues (broad rules, unreachable rules, duplicates).

## 8) Educate and document
Keep a policy authoring playbook and examples; require unique rule IDs and reasons in reviews.

References:
- NIST SP 800-162 ABAC (definition, components, considerations)
- ANSI/INCITS 359-2004 RBAC (roles, permissions, hierarchies)
- XACML 3.0 combining algorithms (deny-/permit-overrides, first-applicable)
