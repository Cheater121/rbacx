# Changelog

All notable changes to this project will be documented in this file.

This project adheres to [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## 1.1.0 – 2025-09-25

### Summary

Adapters were **unified and hardened** around a single decision surface (`Guard.evaluate_async` / `evaluate_sync`) and consistent “deny” behavior. Many adapters now **defer optional framework imports** so the whole package can be imported without those frameworks installed. Diagnostic headers are standardized (`X-RBACX-Reason`, `X-RBACX-Rule`, `X-RBACX-Policy`), while response bodies on deny are intentionally **generic** (“Forbidden”) to avoid leaking policy details.

### Added

* `adapters/_common.py`: new helper types (e.g. `EnvBuilder`) shared across adapter code.
* **ASGI middleware (`adapters/asgi.py`)**: unified JSON responder (`_send_json`) that sets `content-type` and `content-length`, and supports extra headers (bytes, lower-cased) for diagnostics.
* **ASGI logging (`adapters/asgi_logging.py`)**:

  * First-match `traceparent` support: if present, use it as request id; otherwise generate one.
  * Response header emission uses proper **tuple-of-bytes** per ASGI.
* **Django trace middleware (`adapters/django/trace.py`)**:

  * Honors `request.headers` (if available) and accepts W3C `traceparent`, falling back to `X-Request-ID`.
  * Always sets `X-Request-ID` on the response.
* **Litestar middleware (`adapters/litestar.py`)**:

  * Supports both `ASGIMiddleware` (≥2.15) and legacy `AbstractMiddleware`.
  * Adds `handle(...)` delegating to `_dispatch(...)`.
  * Non-HTTP scopes pass through; errors reading `scope['type']` are handled gracefully (debug-logged).

### Changed

* **Optional dependency boundaries** across adapters: modules remain importable even if a given framework (FastAPI, Starlette, Django, DRF, Flask, Litestar) isn’t installed. Errors are raised only when a feature is actually used.
* **FastAPI (`adapters/fastapi.py`)**:

  * Now always uses `guard.evaluate_async(...)` to decide.
  * On deny: body is a **generic** `"Forbidden"`, diagnostics via `X-RBACX-*` headers (when enabled).
* **Starlette (`adapters/starlette.py`)**:

  * Unified decorator logic; async and sync handlers are normalized to a single async path.
  * If a custom deny object isn’t ASGI-callable, it’s coerced into a proper `JSONResponse` with a generic body.
* **Flask (`adapters/flask.py`)**:

  * Adapter is explicitly **sync** and calls `guard.evaluate_sync(...)`.
  * On deny: returns `({"detail":"Forbidden"}, 403, headers)`; diagnostic headers follow the `X-RBACX-*` convention.
* **Django decorators (`adapters/django/decorators.py`)**:

  * Optional imports (module stays importable without Django).
  * On deny: `HttpResponseForbidden("Forbidden")`; optional `X-RBACX-*` headers when enabled.
* **Django middleware (`adapters/django/middleware.py`)**:

  * Optional import of `settings`; attaches the resolved guard to `request.rbacx_guard` for downstream consumers.
* **DRF (`adapters/drf.py`)**:

  * `BasePermission` usage guarded by optional import.
  * Permission class stashes headers onto `request` for the exception handler; the handler injects them into the DRF `Response`.
* **Litestar guard (`adapters/litestar_guard.py`)**:

  * Optional imports; guard raises `PermissionDeniedException(detail="Forbidden", headers=...)`.
  * Headers only included when `add_headers=True` and the corresponding decision fields are present.

### Removed

* `adapters/flask_guard.py` – functionality consolidated into the main Flask adapter (`adapters/flask.py`).

### Fixed

* ASGI response header shape in logging middleware: uses **tuples of bytes** per ASGI spec.
* A number of edge paths across adapters now return consistent status codes and headers, avoiding framework-specific leaks.

### Security

* Deny responses across web adapters now use **generic bodies** to avoid disclosing decision reasons in JSON payloads. If needed, diagnostics are available via headers that can be toggled on per deployment policy.

### Migration notes (from 1.0.0 → 1.1.0)

* **Flask users**

  * Replace any imports/usages of `adapters/flask_guard.py` with the unified `adapters/flask.py` decorator. Behavior is equivalent but deny bodies are now generic (`{"detail":"Forbidden"}`) and diagnostic details, if desired, come via `X-RBACX-*` headers.
* **FastAPI users**

  * If you relied on deny payloads containing a `reason` object, note that the detail is now **“Forbidden”**. Migrate any logic that parsed the body to instead read diagnostic headers (`X-RBACX-Reason`, `X-RBACX-Rule`, `X-RBACX-Policy`) when `add_headers=True` is configured for the dependency.
* **Starlette users**

  * If you returned custom non-ASGI deny objects from guards, they will be auto-coerced into a `JSONResponse`. Ensure any client code expecting a specific payload updates accordingly (deny body is generic; use headers for diagnostics).
* **Django / DRF users**

  * Behavior on deny is unchanged in status but payloads are standardized and headers are the supported channel for diagnostics. For DRF exception handling, keep using the provided `rbacx_exception_handler` so headers stashed by the permission class are copied onto the `Response`.
* **Litestar users**

  * Middleware now supports both modern and legacy bases. If you previously subclassed the adapter or depended on `__call__` only, prefer calling `handle(...)` for ASGI mode; both entry points are present.
  * The guard dependency raises `PermissionDeniedException(detail="Forbidden", headers=...)` with diagnostics only when enabled. Adjust any tests that asserted body-level reasons.
* **General**

  * If you previously parsed deny **bodies** for reasons or rule ids, migrate to **headers** (`X-RBACX-Reason`, `X-RBACX-Rule`, `X-RBACX-Policy`). This change is intentional to reduce information leakage by default.
  * Some internal type imports moved to `adapters/_common.py`. If you referenced internal types directly, update imports accordingly.


## 1.0.0 - 2025-09-21
### Summary
First **stable** release. **No public API changes** compared to `0.9.0`.
Public root imports from `rbacx` are now covered by explicit stability guarantees.
Test coverage has reached **100%**.

### Added
- `DEPRECATION.md` – deprecation policy: removal **after two minor releases or six months** (whichever is later).
- `API_STABILITY.md` – guarantees for stable **root-level imports** starting from `1.x`.
- This changelog entry.

### Changed
- `pyproject.toml`: version bumped to **1.0.0** and classified as **Production/Stable**.

### Deprecated
- None.

### Removed
- None.

### Fixed
- N/A.

### Security
- N/A.

### Migration notes
No action required when upgrading from `0.9.0`. The public API and import paths remain unchanged.


## 0.9.0 — 2025-09-21

### Added

* **Obligations Enforcer** (`rbacx.obligations.enforcer`):

  * New `in_place: bool = False` flag in `apply_obligations(payload, obligations, *, in_place=False)`.
  * By default, the function returns a **deep-copied** payload (no side effects on the original). With `in_place=True`, it mutates the input payload.

* **Decision Logger** (`rbacx.logging.decision_logger`):

  * New `redact_in_place: bool = False` option.
  * Passed through to the enforcer to control whether the `env` is redacted on a copy (default) or **in place**.

### Changed

* **Safe-by-default redaction.**
  The enforcer now uses **deep copy** by default, preventing accidental mutation of application data during masking/redaction.
* The Decision Logger always emits a redacted `env`; behavior is unchanged functionally, but you can now opt into in-place redaction via `redact_in_place=True`.

### Performance

* For large environments or high-throughput pipelines, enable `in_place=True` / `redact_in_place=True` to avoid deep copies and reduce allocations.

### Security

* Copy-by-default reduces the risk of unintended data leakage or side effects when the same structures are reused elsewhere.
* If you need to sanitize sensitive data **before further in-process use**, switch to the explicit **in-place** mode.

### Migration

* If your code **relied on implicit in-place mutation**, enable it explicitly:

  ```python
  from rbacx.obligations.enforcer import apply_obligations

  # In-place redaction
  payload = apply_obligations(payload, obligations, in_place=True)
  ```

  ```python
  from rbacx.logging.decision_logger import DecisionLogger

  # Logger that redacts env in place
  logger = DecisionLogger(redactions=[...], redact_in_place=True)
  ```

### Compatibility

* **Potentially breaking only** for consumers that depended on prior in-place mutation. Set the flags above to restore the previous semantics.


## 0.8.2 — 2025-09-20

### Changed

* Removed unused `type: ignore` annotations across the codebase.
* Replaced all broad `except Exception: pass` with `logger.debug(..., exc_info=True)` for proper diagnostics.

### Tests

* Added/extended adapter branch coverage (ASGI, Django, FastAPI, Flask, Litestar).

### Compatibility

* **No breaking changes.** Public API and behavior remain unchanged.

## 0.8.1 — 2025-09-18

### Fixed

* **HTTP policy source:** on `304 Not Modified` returns the previously cached policy (no accidental empty policy reloads).

### Improved

* **S3 checksums:** correct algorithm labels (e.g., `crc32` is reported as `crc32`), plus support for `crc64nvme`.
  Unified marker format: `ck:<algo>:<value>`.
* **Change markers:** consistent prefixes across strategies:

  * ETag → `etag:<value>`
  * VersionId → `vid:<value>`
  * Checksum → `ck:<algo>:<value>`
    (fallback to `etag:<…>` when data is unavailable)
* **Response headers:** Starlette now emits the canonical header **`X-RBACX-Reason`** (aligned with FastAPI/Flask).

> No breaking changes. Default `add_headers=False` remains unchanged.


## 0.8.0 - 2025-09-18

### Added

* **YAML policy support** across all built-in sources:

  * `FilePolicySource` detects `.yaml` / `.yml` automatically.
  * `HTTPPolicySource` detects YAML via `Content-Type` (e.g., `application/yaml`, `application/x-yaml`, `text/yaml`) or URL suffix.
  * `S3PolicySource` detects YAML via object key suffix.
* **CLI** now accepts YAML files for `rbacx lint --policy ...`.
* **Optional dependency**: `rbacx[yaml]` (uses `PyYAML>=6.0`) for YAML parsing.

### Changed

* **Docs & examples** updated with YAML usage (Quickstart, API notes, policy authoring) and two YAML sample policies (`examples/policies/ok_policy.yaml`, `examples/policies/bad_policy.yaml`).
* `HTTPPolicySource` made more robust and backwards compatible:

  * Prefer `response.json()` for non-YAML content (keeps existing tests/mocks working).
  * Fallback to text/content parsing; case-insensitive headers (captures `ETag` regardless of header casing).

### Security

* YAML is parsed with `yaml.safe_load` to avoid executing arbitrary constructors.

### Tests

* Added comprehensive tests for YAML flows and S3/HTTP sources, including negative cases and optional-dependency skips for CI.

### Migration notes

* To use YAML policies, install the extra:

  ```bash
  pip install "rbacx[yaml]"
  ```
* No HTTP contracts or JSON Schema changed; YAML policies are validated against the same schema as JSON.


## 0.7.0 — 2025-09-17

*“Async-first core, zero new deps, full sync compatibility.”*

### Added
- **Async evaluation core** in `Guard`:
  - `evaluate_async(...)` and `is_allowed_async(...)` for ASGI frameworks.
  - CPU-bound policy evaluation (`policy` / `policyset` / compiled fn) is offloaded via `asyncio.to_thread(...)` to keep the event loop responsive.
- **Optional async DI ports** (Variant A typing):
  - `DecisionLogSink.log`, `MetricsSink.inc/observe`, `RoleResolver.expand`, `ObligationChecker.check`, and `PolicySource.load/etag` now accept **sync or async** implementations (`T | Awaitable[T]`).
- **Async-aware reloader**:
  - `HotReloader.check_and_reload_async(...)` (single source of truth).
  - The sync method `check_and_reload(...)` bridges safely from sync code and from within a running event loop.
- **New tests** covering async DI, thread offload, obligation auto-deny, reloader suppression/backoff, and sync-wrapper-in-event-loop scenarios.

### Changed
- **Single source of truth**: both sync and async paths delegate to one async core in `Guard` and `HotReloader`, removing duplication.
- **Non-blocking behavior**:
  - In async contexts, heavy/CPU work is offloaded with `to_thread`; sync wrappers run the core in a helper thread if a loop is already running.
  - Obligation checks, metrics, and logging are **conditionally awaited** when async; otherwise called as-is.
- **Ports typing** (`rbacx.core.ports`):
  - Protocols widened to `T | Awaitable[T]` for DI points listed above (no runtime dependency added).
- **Docs**:
  - `policy_loading.md`: added “Sync vs Async usage” and clarified that `PolicySource` may be sync **or** async.
  - `policy_stores.md`: updated protocol snippet to the new union types.
  - `highlights.md`: noted async support in `Guard`/`HotReloader` and sync/async-friendly ports.

### Fixed
- **Python 3.12 event-loop compatibility**: legacy `get_event_loop().run_until_complete(...)` flows no longer error—`Guard` gently ensures a current loop when needed.
- **Obligations**: unfulfilled obligations now consistently switch effect to `deny` with `reason="obligation_failed"` and propagate `challenge`.

### Performance & Reliability
- Reduced event-loop blocking under ASGI due to thread offloading.
- Reloader avoids holding locks across awaits and continues to apply exponential backoff + jitter after errors.

### Compatibility
- **No breaking changes.** Existing **sync** adapters, sources, and sinks continue to work unchanged.
- **Type-safety note**: if your own code declared **stricter** custom Protocols for ports, update them to the new `T | Awaitable[T]` shape to match the official interfaces.


## 0.6.0 — 2025-09-17

### Added
- **Metrics adapters:** optional `observe(name, value, labels=None)` skeletons in both `PrometheusMetrics` and `OpenTelemetryMetrics`. Guard will call `observe` *iff* the adapter exposes it. No SDK → safe no-op.
- **Policy schema:** support `algorithm: "first-applicable"` in `policy.schema.json`.
- **Package root imports:** convenient re-exports — `from rbacx import Guard, Subject, Action, Resource, Context, HotReloader, load_policy`.

### Changed
- **Guard behavior — obligations:** when a policy returns *permit* but an obligation is **not** fulfilled, Guard now **denies** the request and sets `reason="obligation_failed"` (challenge is preserved if present). **BREAKING** for callers that previously treated unfulfilled obligations as “permit + challenge”.
- **Metrics naming unified:**
  - Counter → `rbacx_decisions_total{decision=...}`
  - Latency histogram → `rbacx_decision_seconds`
  Names follow Prometheus conventions (`_total`, include base unit in name), OTel uses `unit="s"` while keeping `_seconds` for Prometheus interoperability. **Update dashboards/alerts accordingly.**
- **README — Decision schema:** clarified fields: `decision`, bounded `reason` set, `rule_id` **and** `last_rule_id`, optional `policy_id` (for policy sets).
- **Docs — Policy format:** examples standardized on `actions` + `resource { type, attrs }` (removed legacy `target` example).
- **Docs — Audit mode:** clarified that when a listed field is missing, enforcer still writes it in the logged `env` with a placeholder (masked or `[REDACTED]`) before logging.

### Deprecated
- _None._ (Previously deprecated APIs removed below.)

### Removed
- **Deprecated loaders/managers:**
  - `rbacx.store.manager.PolicyManager` (module now raises a clear `ImportError` with the migration hint).
  - `rbacx.policy.loader.ReloadingPolicyManager`.
  Use `rbacx.policy.loader.HotReloader` instead.

### Fixed / Tooling
- **mypy:** explicit attribute types for metrics adapters (`_counter`, `_hist`) to resolve “Cannot determine type” errors.
- **Tests:**
  - New unit tests for metrics `observe(...)` (SDK present vs. absent).
  - Updated tests to `HotReloader` and to the new Guard obligation behavior.
  - Metrics adapter tests updated to the unified names.

### Documentation
- **New page:** *Custom PolicySource (minimal)* — in-memory example + checklist/best practices; added to MkDocs navigation under **Policy** (right after “Policy loading (hot reload)”).
- **README / guides** updated to use simplified imports: `from rbacx import Guard, ...`.

---

## Migration guide

**Obligations auto-deny (BREAKING):**
- If your application relied on “permit with unmet obligations”, expect **deny** now (with `reason="obligation_failed"`).
- Ensure your obligation checker returns `ok=True` only when obligations are truly satisfied; clients should continue to honor any `challenge` provided.

**Metrics:**
- Update dashboards/alerts to the new names:
  - `rbacx_decisions_total{decision=...}`
  - `rbacx_decision_seconds`
  Naming follows Prometheus best practices; OTel keeps `unit="s"`.

**Imports:**
- Prefer concise imports:
  ```python
  from rbacx import Guard, Subject, Action, Resource, Context, HotReloader, load_policy
  ```

**Loaders:**
- Replace `PolicyManager` / `ReloadingPolicyManager` with `HotReloader`.

**Policy schema:**
- You can now use `algorithm: "first-applicable"` in policy sets.


## 0.5.2 — 2025-09-16

**Critical hotfix — please update.**

### Security
- Guard’s decision logging now passes the entire evaluation environment under `env` to the `DecisionLogSink`. This ensures `DecisionLogger` can apply redaction/obligation rules consistently. Previous versions could emit sensitive fields in cleartext at the top level; this release protects logs via proper redaction.

### Fixed
- Declare and enforce `Requires-Python >= 3.10` (package metadata + runtime check) to prevent import/collection errors on older interpreters.

_No public API changes._


## 0.5.1 — 2025-09-16

### Added
- New compiler edge tests covering normalization of `actions` (dict keys, sets, generators), wildcard and list/tuple types for `resource.type`, and invalid inputs (None, wrong types).
- Tests for policyset vs policy, empty rule selection, unknown algorithm fallback.
- Integration test for Flask adapter: `require_access(add_headers=True)` verifying header and reason field behavior.

### Fixed
- Guard constructor signature aligned: removed deprecated `obligations` parameter usage in tests.
- Flask adapter: reason header checked instead of JSON body field to match actual behavior.
- S3 store checksum and ETag parsing corrections in tests; tests skip when `boto3` missing.

### Coverage
- Compiler module coverage raised from ~82% to ~95%, closing many branch-cases and guard paths.


## 0.5.0 — 2025-09-14

### Added
- Decision logger: **JSON serialization option** for events and **configurable log level**.

### Changed
- Ports: renamed protocol `DecisionLogger` → `DecisionLogSink` to clarify outbound logging sink.
- Docs: updated `highlights.md` and `index.md`.

### Fixed
- Metrics: `rbacx.metrics.otel` and `rbacx.metrics.prometheus` now explicitly import and implement `MetricsSink`, aligning implementations with the interface.

### Removed
- Telemetry: removed package marker and unused duplicate implementations (simple Prometheus sink and decision logger).
- Docs: removed redundant `decision_log` section from `api.md`.

### Migration / Notes
- Update imports and type hints:
  ```python
  # before
  from rbacx.core.ports import DecisionLogger
  # after
  from rbacx.core.ports import DecisionLogSink
  ```
- If you referenced removed telemetry implementations, switch to the sinks in `rbacx.metrics.prometheus` / `rbacx.metrics.otel` and the logging adapter in `rbacx.logging`.
- To record latency histograms, implement optional `MetricsObserve` in your sink (e.g., `PrometheusMetricsObserver`).


## 0.4.3 — 2025-09-13

### Fixed
- Django decorator: added stub for `HttpRequest` to support `from django.http import HttpRequest` in decorators so tests with minimal Django no longer fail.
- Django decorator: ensure `audit=False` mode properly raises `PermissionDenied` or returns `HttpResponseForbidden` (status 403).
- Litestar adapter middleware: fixed importing issues by using correct stub for `AbstractMiddleware` and isolating imports so real Litestar is not required during test collection.
- HTTP policy source: improved import isolation for `requests`: test now forces `ImportError` on missing `requests` module so code path for missing dependency is covered.

### Added
- New integration tests for `rbacx.adapters.django.decorators` covering `audit=True` vs `audit=False`.
- Additional branches covered in `rbacx.metrics.otel` and `rbacx.metrics.prometheus` for missing-client/SDK and minimal stub scenarios.
- Additional test for HTTP source missing dependency behaviour.

### Changed
- Test coverage increased; several formerly unstable or failing test cases are now reliable under stubbed dependencies.

### Migration / Notes
- If you have custom decorators or settings relying on `HttpRequest` being available, ensure you consider the new stub behaviour in tests.
- For users who override Django adapters or decorator behaviour: check that your `audit` configuration is respected (i.e. `audit=True` allows vs `audit=False` denies).


## 0.4.2 — 2025-09-13
### Fixed
- **HotReloader example** in README updated to new feature.

## 0.4.1 — 2025-09-13

### Added
- **HotReloader** startup controls:
  - `initial_load: bool = False` — when `True`, the first `check_and_reload()` loads the current policy without priming the ETag (safe startup).
  - `check_and_reload(force: bool = False)` — `force=True` bypasses the ETag check and loads the policy unconditionally.
  - `start(..., initial_load: bool | None = None, force_initial: bool = False)` — optional synchronous initial load before the polling thread starts; `force_initial=True` ignores ETag for that first load.
- Diagnostics: exposed properties remain (`last_etag`, `last_reload_at`, `last_error`, `suppressed_until`) for observability.
- Documentation: expanded **Policy loading (hot reload)** page with startup patterns and operational guidance.

### Changed
- Default behavior remains **backwards-compatible**: `initial_load=False` primes the ETag at construction; the first `check_and_reload()` is a NO-OP unless the source’s ETag changes.
- Logging/robustness: clearer messages on force-loaded vs. ETag-driven reloads; unchanged backoff + jitter strategy on errors.

### Deprecated
- **`rbacx.policy.loader.ReloadingPolicyManager`** — constructing this wrapper now emits a `DeprecationWarning` and a log warning; it delegates to `HotReloader` with legacy semantics (`initial_load=False`).
- Reminder: **`rbacx.store.manager.PolicyManager`** remains deprecated; prefer `HotReloader` with a `PolicySource` (e.g., `FilePolicySource`).

### Tests
- Added/updated integration tests to cover:
  - `initial_load=True` (loads on the first check).
  - `force=True` path regardless of ETag.
  - `start(initial_load=True, force_initial=True)` synchronous bootstrap.
  - Deprecation warnings for `ReloadingPolicyManager` and compatibility delegation.

### Migration
- For **safe startup**, construct `HotReloader(..., initial_load=True)` and call `check_and_reload()` during app boot, or call `start(initial_load=True, force_initial=True)`.
- Replace `ReloadingPolicyManager` (and legacy `PolicyManager`) with `HotReloader`:

  ```python
  # BEFORE (deprecated)
  from rbacx.store.manager import PolicyManager
  mgr = PolicyManager(guard, source)

  # AFTER
  from rbacx.policy.loader import HotReloader
  mgr = HotReloader(guard, source, initial_load=True)
  mgr.check_and_reload()


## 0.4.0 — 2025-09-13

### Added
- **S3PolicySource** with flexible change detection and checksum fallback.
- **HotReloader**: unified, documented policy reloader with consistent behavior across sources.
- Web adapters: robust `require_access(...)` wrappers for **Starlette** and **FastAPI** that always return ASGI-callable responses in route/decorator mode; optional denial headers (`x-rbacx-reason`) retained.
- New/updated examples (including Litestar) and docs for adapters, policy stores, audit mode, and quickstart.

### Changed
- Storage: `FilePolicySource` and `HotReloader` internals streamlined; improved reload semantics and portability (Windows tempfiles).
- Tests overhauled for web adapters; CI coverage badge updated.
- Restored legacy `PolicyManager` constructor signature and initial apply semantics to preserve short-term compatibility (see **Deprecated**).

### Deprecated
- `rbacx.store.manager.PolicyManager` — use `rbacx.policy.loader.HotReloader` instead for consistent reload behavior.

### Fixed
- Starlette/FastAPI adapters: resolved coroutine vs callable issues and `JSONResponse` callability when tests monkeypatch response classes.
- Django/DRF test flakiness and several example bugs:
  - `basic_quickstart.py`: rule specificity now matches compiler bucket selection → correct **permit**.
  - `conditions_time.py`: time condition reads `context.when` (not `context.attrs.when`).
  - `hotreload_file.py`: prints decision effect and closes/rewrites temp files correctly on Windows.

### Migration
- Replace `PolicyManager` with `HotReloader`:

  ```python
  # BEFORE (deprecated)
  from rbacx.store.manager import PolicyManager
  mgr = PolicyManager(guard, source)

  # AFTER
  from rbacx.policy.loader import HotReloader
  mgr = HotReloader(guard, source)
  mgr.check_and_reload()


## 0.3.2 - 2025-09-11

### Fixed
- **Coverage badge** link in README updated to absolute raw GitHub URL so it displays correctly on PyPI.

## 0.3.1 — 2025-09-11

### Fixed
- **Architecture diagram** now renders correctly on GitHub Pages:
  - enabled native Mermaid support via `pymdownx.superfences` with a `mermaid` custom fence in `mkdocs.yml`.
- Resolved docs build error caused by older **mkdocstrings ↔ mkdocs-autorefs** combo
  (`AttributeError: 'dict' object has no attribute 'link_titles'`) by upgrading both and
  adding `autorefs` to `plugins`.

### Changed
- **Docs toolchain upgraded** and pinned in CI:
  - `mkdocs` `1.6.x`
  - `mkdocs-material` `>=9.5.19,<10`
  - `mkdocstrings[python]` `>=0.26.2,<1`
  - `mkdocs-autorefs` `>=1.4.2,<2`
- Updated `[project.optional-dependencies].docs` in `pyproject.toml` to reflect the same versions.

### Notes
- No changes to the runtime package or public API. Documentation-only maintenance release.


## 0.3.0 — 2025-09-11
### Added
- **Landing page** (`docs/index.md`) with philosophy, Quick start, and a documentation map.
- **Decision object** section in `docs/api.md` describing the exact fields returned by `Guard.evaluate*`.
- **Why choose RBACX** and **Highlights** pages refined and consolidated.

### Changed
- **Navigation restructured** in `mkdocs.yml` (Getting started / Concepts / Policy / Integration / Observability / Performance / Operations / Reference).
- **Examples updated** to use `from rbacx.core.engine import Guard` and `evaluate_sync(...)`.
- **Hot-reload documentation** (`policy_loading.md`) aligned with current behavior (ETag polling, `Guard.set_policy(...)`).
- Wording and tone adjusted to be **developer-centric** (more facts, fewer opinions).

### Fixed
- Removed duplicated introductions across multiple pages (kept a single canonical intro).
- Corrected minor terminology mismatches and outdated snippets in docs.

### Removed
- Repeated “what is RBACX / RBAC+ABAC / hot reload” blurbs from subpages.

### Notes
- **No breaking changes.** Library runtime and public API unchanged in this release.


## 0.2.1 — 2025-09-11
### Changed
- **Test suite layout:** Reorganized into a layered structure for clarity and faster targeted runs:
  - `tests/unit/{core,dsl,engine,imports,logging,metrics,pkg,policyset}`
  - `tests/integration/{adapters/{asgi,django,flask,litestar,starlette,web},engine,metrics,storage,store,telemetry}`
  - `tests/e2e/cli`

### Added
- **Dev/test dependencies:** `pytest-asyncio` to enable first-class testing of `async def` tests and async fixtures.


## 0.2.0 — 2025-09-10
### Improved
- **Test Coverage**: Expanded test suite to push overall coverage above 80%, especially around middleware, adapters, and core logic.
- **CI Pipeline**: Integrated code coverage badge generation and automated updates to README via GitHub Actions.

### Added
- New tests for:
  - Django middleware factories
  - Starlette adapter behavior with/without dependencies
  - ASGI access log functionality
  - CLI tooling and argument parsing
  - Core engine, policy evaluation, and policy-set logic
  - Storage and telemetry modules

### Fixed
- Resolved test collection errors due to missing package imports in CI—corrected install strategy to ensure modules are discoverable (`pip install -e .`) before running pytest.


## 0.1.1 — 2025-09-09
### Fixed
- MkDocs build: added `paths: [src]`, installed `mkdocstrings(-python)` in CI; fixed nav paths.
- API docs: ensured packages are importable for mkdocstrings; added missing `__init__.py`.
- CI: split workflows (CI/Docs/Release), coverage artifact on Python 3.11 only.
- mypy: ignore_missing_imports overrides for optional frameworks (Django/Litestar).

### Changed
- README/docs polishing; real links to repo and Pages.

## 0.1.0 — Initial public release
- Type-safe condition evaluation with strict type mismatch reporting
- Policy algorithms: deny-overrides, permit-overrides, first-applicable
- Policy sets evaluator
- Hot reload helpers (file source + polling manager)
- Linter for overlapping/required/duplicate rules
- Examples and updated docs
