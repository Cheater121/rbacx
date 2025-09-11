# Changelog

## 0.2.1 — 2025-09-11
### Changed
- **Test suite layout:** Reorganized into a layered structure for clarity and faster targeted runs:
  - `tests/unit/{core,dsl,engine,imports,logging,metrics,pkg,policyset}`
  - `tests/integration/{adapters/{asgi,django,flask,litestar,starlette,web},engine,metrics,storage,store,telemetry}`
  - `tests/e2e/cli`
- **Conventions:** Maintain `tests/conftest.py` at the test root; omit `__init__.py` in test folders to keep them as plain test directories.

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
