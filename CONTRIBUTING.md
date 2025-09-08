
# Contributing to RBACX

Thanks for your interest!

## Dev setup
```bash
python -m venv .venv && source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e .[dev,tests,docs,examples,validate]
pre-commit install
```

## Running checks
```bash
ruff check src
ruff format --check
mypy src
pytest -q
```

## Commit style
- Follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/).
- Keep PRs small and focused; include tests and docs where possible.

## Code of Conduct
This project follows the Contributor Covenant v2.1. See `CODE_OF_CONDUCT.md`.
