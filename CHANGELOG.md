# Changelog

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
