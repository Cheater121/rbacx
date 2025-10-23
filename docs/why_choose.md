## Quick Comparison (at a glance)

| Criterion                       | **RBACX (Python)**                                                                                           | **Casbin (Python)**                                                                                     | **Oso (Polar + Python SDK)**                                                         | **Django Guardian**                                           | **django-rules**                                              | **Flask-RBAC**                                   |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ | ------------------------------------------------------------- | ------------------------------------------------------------- | ------------------------------------------------ |
| **Policy definition**           | JSON/YAML/Python dicts (declarative data + operators; includes ReBAC `rel` condition)                        | Separate `model.conf` + policy storage (CSV/DB/etc.)                                                    | Separate `.polar` files; declarative DSL (Polar)                                     | No DSL; permissions stored in DB; backend checks              | No DSL; rules/predicates registered in Python                 | In-code decorators/config registering role rules |
| **Framework integration**       | Adapters for FastAPI, Flask, Django/DRF, Starlette/Litestar (middleware/deps/decorators)                     | Library calls (`enforcer.enforce(...)`); framework glue typically user-built                            | Enforce via `authorize()` in app code; ORM filtering helpers                         | Django-only; integrates with `user.has_perm` and Django Admin | Django-only backend; integrates with `has_perm` & DRF helpers | Flask-only; extension + decorators               |
| **Query-time filtering**        | Manual in app/repo layer                                                                                     | Manual or custom helpers                                                                                | Helpers like `authorized_query` / `authorized_resources` for ORMs                    | ORM patterns (filter by permissions)                          | Manual (apply predicates or integrate with queryset logic)    | N/A (endpoint/role checks)                       |
| **ReBAC (relationship checks)** | Optional `RelationshipChecker`; optional connectors to external relationship stores (e.g., SpiceDB, OpenFGA) | Model via roles/domains or ABAC functions; no first-class relationship graph backend in core usage docs | Can model relationships in Polar and filter data; no external graph backend required | Object permissions model (per-object grants)                  | Predicate-based checks; no relationship graph                 | Simple role checks; no relationship graph        |
| **Language scope**              | Python                                                                                                       | Multi-language ecosystem                                                                                | Libraries for multiple languages                                                     | Python/Django                                                 | Python/Django                                                 | Python/Flask                                     |

**Notes for the table:** Casbin uses a `model.conf` + policy storage (commonly CSV) architecture; Oso policies are written in the Polar language; Guardian provides Django object permissions; `django-rules` is predicate-based; Flask-RBAC adds RBAC to Flask.

---

## Advantages of RBACX

RBACX brings together role-based, attribute-based, and **relationship-based** access control (ReBAC). You can start with simple role checks and add attribute- or relationship-based conditions later—without changing libraries or architecture. Many alternatives focus either on roles (e.g., Flask-RBAC, Casbin in its simplest use) or a dedicated DSL (e.g., Oso), whereas RBACX supports **RBAC + ABAC + ReBAC** in one engine. ReBAC can leverage external relationship stores such as **SpiceDB** or **OpenFGA** when configured.

* **Straightforward policy format**
  Policies are JSON/YAML (or Python dicts). Unlike Casbin (separate model + data) or Oso (a dedicated language), RBACX uses familiar configuration formats that non-programmers can review. The condition DSL is compact but expressive for common business rules. Example:

  ```json
  {"==": [ {"attr": "resource.owner"}, {"attr": "subject.id"} ]}
  ```

  makes the “owner” check explicit. Polar’s equivalent (`resource.owner == user`) is concise but requires learning a new DSL.

* **Clean, extensible codebase**
  RBACX is modular and easy to customize. If you want to store policies in PostgreSQL, implement a `PostgresPolicySource` and plug it into `Guard`—no need to fork the library. Casbin is also extensible but has a steeper model/policy abstraction; Oso’s engine centers around a DSL rather than pluggable ports.

* **Adapters for multiple frameworks**
  Out of the box, RBACX provides adapters for FastAPI/Starlette, Flask, Django, and Litestar. This shortens integration time and enables the same authorization model across services built with different frameworks. In contrast, some alternatives are tied to one framework (Guardian → Django, Flask-RBAC → Flask) or require custom glue (Casbin, Oso).

* **Hot policy reload**
  RBACX can watch file/HTTP/S3 sources and apply policy updates automatically using ETag checks. Guardian, `rules`, and Flask-RBAC do not provide this out of the box; Casbin supports policy adapters and watchers, and Oso typically reloads programmatically.

* **Explainability, obligations, and ReBAC**
  RBACX decisions expose not only Permit/Deny but also *why* (e.g., `reason`, `rule_id`) and can include **obligations** (e.g., require MFA). With ReBAC enabled, the engine can consult a relationship store (e.g., SpiceDB/OpenFGA) through a `RelationshipChecker` port.

* **Lightweight with minimal dependencies**
  RBACX keeps the dependency footprint small (e.g., JSON Schema for validation), simplifying installation and reducing exposure to third-party vulnerabilities.

* **Optional decision cache** to reduce latency on repeat checks, with safe invalidation on policy change.

---

## Verdict

RBACX delivers RBAC + ABAC + **ReBAC** with a declarative JSON policy model, secure defaults, combining algorithms, hot reload, explainable decisions, and ready-to-use adapters for major Python web frameworks. It’s a pragmatic choice for teams that want fine-grained, auditable authorization without adopting a new policy language. For systems that store permissions as relationships (Google Zanzibar–style), RBACX can delegate checks to proven backends like **SpiceDB** or **OpenFGA**.

> **Disclaimer**: This page reflects the library author’s perspective. For projects that require **100% reliability proven by years of production use**, the choice may lean toward more mature and widely adopted solutions.
