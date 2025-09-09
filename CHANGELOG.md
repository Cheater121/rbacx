# Changelog

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
