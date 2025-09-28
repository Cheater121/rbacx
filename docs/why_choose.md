## Quick Comparison (at a glance)

| Criterion | **RBACX (Python)** | **Casbin (Python)** | **Oso (Polar + Python SDK)** | **Django Guardian** | **django-rules** | **Flask-RBAC** |
|---|---|---|---|---|---|---|
| **Policy definition** | JSON/YAML/Python dicts (declarative data + operators) | Separate `model.conf` + policy storage (CSV/DB/etc.) | Separate `.polar` files; declarative DSL | No DSL; permissions stored in DB; backend checks | No DSL; rules/predicates registered in Python | In-code decorators/config registering role rules |
| **Framework integration** | Adapters for FastAPI, Flask, Django/DRF, Starlette/Litestar (middleware/deps/decorators) | Library calls (`enforcer.enforce(...)`); framework glue typically user-built | Enforce via `authorize()` in app code; ORM filtering helpers | Django-only; integrates with `user.has_perm` and Django Admin | Django-only backend; integrates with `has_perm` & DRF helpers | Flask-only; extension + decorators |
| **Query-time filtering** | Manual in app/repo layer | Manual or custom helpers | Helpers like `authorized_query` / `authorized_resources` for ORMs | ORM patterns (filter by permissions) | Manual (apply predicates or integrate with queryset logic) | N/A (endpoint/role checks) |
| **Language scope** | Python | Multi-language ecosystem | Libraries for multiple languages | Python/Django | Python/Django | Python/Flask |

---

## Advantages of RBACX

  RBACX brings together role-based and attribute-based access control. You can start with simple role checks and add attribute-based conditions later—without changing libraries or architecture. Many alternatives focus either on roles (e.g., Flask-RBAC, Casbin in its simplest use) or attributes (e.g., Oso, `rules`), whereas RBACX supports both approaches from the start.

- **Straightforward policy format**
  Policies are JSON/YAML (or Python dicts). Unlike Casbin (separate model + data) or Oso (a dedicated language), RBACX uses familiar configuration formats that non-programmers can review with care. The condition DSL is intentionally compact but sufficiently expressive for common business rules. For example:
  ```json
  {"==": [ {"attr": "resource.owner"}, {"attr": "subject.id"} ]}
  ```
  makes the “owner” check explicit. In Polar, the equivalent `resource.owner == user` is shorter but requires context on objects and language semantics. RBACX policies are easy to version and to send for security review.

- **Clean, extensible codebase**
  RBACX is modular and easy to customize. If you want to store policies in PostgreSQL, implement a `PostgresPolicySource` and plug it into `Guard`—no need to fork or patch the library. Casbin is also extensible but has a steeper API/model learning curve; Oso’s engine is not designed for user-level engine extensions. RBACX is pure Python, so teams can audit, extend, or patch it directly. Code readability makes maintenance and debugging simpler.

- **Adapters for multiple frameworks**
  Out of the box, RBACX provides adapters for FastAPI/Starlette, Flask, Django, and Litestar. This shortens integration time and enables the same authorization model across services built with different frameworks. In contrast, some alternatives are tied to one framework (Guardian → Django, Flask‑RBAC → Flask) or require custom glue code (Casbin, Oso).

- **Hot policy reload**
  RBACX can watch file/HTTP/S3 sources and apply policy updates automatically using ETag checks. This suits dynamic environments where policies are frequently modified or centrally stored (e.g., S3). Guardian, `rules`, and Flask‑RBAC do not provide this out of the box; Casbin partially covers it (manual reload/watchers), while Oso library generally requires programmatic reloads.

- **Explainability and obligations**
  RBACX decisions expose not only Permit/Deny but also *why* (e.g., `reason`, `rule_id`) and can include **obligations** (e.g., require MFA). Explainability aids debugging and audits. Competing libraries may not offer obligations in their open-source variants or return only a boolean decision.

- **Lightweight with minimal dependencies**
  RBACX keeps the dependency footprint small (e.g., **jsonschema** for policy validation). A smaller footprint simplifies installation and reduces exposure to third‑party vulnerabilities.

- **Optional decision cache** to reduce latency on repeat checks, with safe invalidation on policy change.

---

## Verdict

RBACX delivers RBAC+ABAC with a declarative JSON policy model, secure defaults, combining algorithms, hot reload, explainable decisions, and ready-to-use adapters for major Python web frameworks. It’s a pragmatic choice for teams that want fine-grained, auditable authorization without adopting a new policy language.

> **Disclaimer**: This page reflects the library author’s perspective. For projects that require **100% reliability proven by years of production use**, the choice may lean toward more mature and widely adopted solutions.
