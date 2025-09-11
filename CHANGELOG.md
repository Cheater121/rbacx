# Changelog

## 0.3.1 - 2025-09-11

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


## 0.3.0 - 2025-09-11
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
