# Highlights of RBACX

## Architecture & Design

* **Core vs. Adapters**: Authorization decision logic lives in `rbacx.core` (e.g., `Guard`), while framework-specific integration is implemented as adapters (FastAPI, Django, Flask, DRF, Starlette/Litestar). This separation keeps the core framework-agnostic.
* **Ports/Interfaces**: Core depends on abstract ports (sync/async-friendly; e.g., `RoleResolver`, `DecisionLogSink`, `MetricsSink`, `ObligationChecker`) enabling custom implementations without modifying the core.
* **Security defaults**: The default combining algorithm is `deny-overrides` (deny-by-default). Other algorithms: `permit-overrides`, `first-applicable`.
* **ReBAC port**: Optional `RelationshipChecker` in `rbacx.core.ports` with ready-to-use implementations: `LocalRelationshipChecker`, `SpiceDBChecker`, `OpenFGAChecker`. Enables relationship-based checks (subject —relation→ resource) alongside RBAC/ABAC.

## Policy Model (JSON)

* **Entities**: `Subject`, `Resource`, `Action`, plus optional context.
* **Rules & Effects**: Each rule defines conditions and an `effect` (Permit/Deny).
* **Combining algorithms**: `deny-overrides` (default), `permit-overrides`, `first-applicable`.
* **Conditions**: comparisons (`==`, `!=`, `<`, `<=`, etc.), collection operations (`hasAny`, `hasAll`), membership (`in`, `contains`), and time operators (`before`, `after`, `between`).
* **Relationship conditions (ReBAC)**: `rel` operator for graph/relationship checks.
  Short form: `{"rel": "owner"}` (uses current subject/resource).
  Extended: `{"rel": {"relation": "editor", "subject": "...", "resource": "...", "ctx": {...}}}`.
  If `subject`/`resource` omitted, engine uses inputs; `ctx` is merged into `context._rebac`. If no `RelationshipChecker` is configured, `rel` evaluates to `false` (fail-closed).
* **Obligations**: actions to perform on Permit decisions (e.g., require MFA, log an event).

## Integration

* **Frameworks**: Adapters for FastAPI, Flask, Django (incl. DRF), Starlette/Litestar.
* **Enforcement**: Dependencies/middleware/decorators (e.g., `rbacx.adapters.fastapi.require_access`) to guard endpoints, views, or request pipelines.
* **Role Resolution**: Pluggable role resolvers (e.g., static role inheritance with `StaticRoleResolver`).
* **Enable ReBAC**: Pass `relationship_checker=` to `Guard(...)`. Sync/async implementations are supported; framework adapters do not require changes.

## Policy Loading & Reloading

* **Sources**: Filesystem, HTTP(S), AWS S3.

## Observability & Tooling

* **Decision Introspection**: Decision objects expose fields such as `allowed`, `effect`, `reason`, `rule_id`, enabling audit and explainability.
* **Metrics & Logging**: Sinks for Prometheus / OpenTelemetry and structured logging are pluggable via ports.
* **Linting**: Policy linter/CLI to validate policy consistency before/at runtime.

## Testing

* **Coverage**: Meets industry standards. Approximately **80+%** of the codebase.
* **Scope**: Tests cover decision logic, rule combining, ABAC operators (including time and collection ops), obligations, policy loading/reloading, and linting.

## Performance Considerations

* Internal indexing/compilation of policies to quickly skip irrelevant rules (e.g., by resource type).
* Stateless `Guard` suitable for horizontal scaling; shared policy sources (e.g., S3/file) can be used across instances.
* Documentation includes guidance on avoiding overly broad conditions and caching expensive context computations.
* **ReBAC checks**: Relationship lookups are memoized within a single decision; backends may implement `batch_check(...)` to reduce round-trips for bulk evaluations.

## Compatibility

* **Python**: see project metadata (pyproject.toml).
* **Frameworks**: FastAPI, Flask, Django/DRF, Starlette/Litestar (via adapters).

## Async support

* `Guard` provides both `evaluate_sync(...)` and `evaluate_async(...)`. Injected ports (resolver, obligations, metrics, logger) can be synchronous **or** asynchronous; both forms are supported.
* `HotReloader` provides `check_and_reload(...)` (sync) and `check_and_reload_async(...)` (async) and accepts `PolicySource` implementations with sync or async `load()`/`etag()`.
