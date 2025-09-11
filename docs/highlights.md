# Highlights of RBACX

## Architecture & Design

- **Core vs. Adapters**: Authorization decision logic lives in `rbacx.core` (e.g., `Guard`), while framework-specific integration is implemented as adapters (FastAPI, Django, Flask, DRF, Starlette/Litestar). This separation keeps the core framework‑agnostic.
- **Ports/Interfaces**: Core depends on abstract ports (e.g., `RoleResolver`, `DecisionLogger`, `MetricsSink`, `ObligationChecker`) enabling custom implementations without modifying the core.
- **Security defaults**: The default combining algorithm is `deny-overrides` (deny-by-default). Other algorithms: `permit-overrides`, `first-applicable`.

## Policy Model (JSON)

- **Entities**: `Subject`, `Resource`, `Action`, plus optional context.
- **Rules & Effects**: Each rule defines conditions and an `effect` (Permit/Deny).
- **Combining algorithms**: `deny-overrides` (default), `permit-overrides`, `first-applicable`.
- **Conditions**: comparisons (`==`, `!=`, `<`, `<=`, etc.), collection operations (`hasAny`, `hasAll`), membership (`in`, `contains`), and time operators (`before`, `after`, `between`).
- **Obligations**: actions to perform on Permit decisions (e.g., require MFA, log an event).

## Integration

- **Frameworks**: Adapters for FastAPI, Flask, Django (incl. DRF), Starlette/Litestar.
- **Enforcement**: Dependencies/middleware/decorators (e.g., `rbacx.adapters.fastapi.require_access`) to guard endpoints, views, or request pipelines.
- **Role Resolution**: Pluggable role resolvers (e.g., static role inheritance with `StaticRoleResolver`).

## Policy Loading & Reloading

- **Sources**: Filesystem, HTTP(S), AWS S3.

## Observability & Tooling

- **Decision Introspection**: Decision objects expose fields such as `allowed`, `effect`, `reason`, `rule_id`, enabling audit and explainability.
- **Metrics & Logging**: Sinks for Prometheus / OpenTelemetry and structured logging are pluggable via ports.
- **Linting**: Policy linter/CLI to validate policy consistency before/at runtime.

## Testing

- **Coverage**: Meets industry standards. Approximately **80+%** of the codebase.  
- **Scope**: Tests cover decision logic, rule combining, ABAC operators (including time and collection ops), obligations, policy loading/reloading, and linting.

## Performance Considerations

- Internal indexing/compilation of policies to quickly skip irrelevant rules (e.g., by resource type).
- Stateless `Guard` suitable for horizontal scaling; shared policy sources (e.g., S3/file) can be used across instances.
- Documentation includes guidance on avoiding overly broad conditions and caching expensive context computations.

## Compatibility

- **Python**: see project metadata (pyproject.toml / setup.cfg).
- **Frameworks**: FastAPI, Flask, Django/DRF, Starlette/Litestar (via adapters).

## Verdict

