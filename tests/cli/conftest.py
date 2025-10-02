
import importlib.util
import pytest

def _has_module(modname: str) -> bool:
    """Return True if the given module can be imported (present on sys.path)."""
    return importlib.util.find_spec(modname) is not None

def pytest_collection_modifyitems(config, items):
    """Dynamically skip tests that require optional dependencies.

    - Skip *validation-driven* CLI tests when 'jsonschema' is not installed.
      These tests typically have 'validate' in their nodeid.
      One known 'check' test also depends on validation and is skipped explicitly.
    - Skip *YAML-driven* CLI tests when 'PyYAML' (import name: 'yaml') is not installed.
      These tests typically have 'yaml' in their nodeid.
    """
    missing_jsonschema = not _has_module("jsonschema")
    missing_yaml = not _has_module("yaml")

    if not (missing_jsonschema or missing_yaml):
        return

    skip_validate = pytest.mark.skip(reason="optional dependency 'jsonschema' not installed; skipping schema-validation tests")
    skip_yaml = pytest.mark.skip(reason="optional dependency 'PyYAML' not installed; skipping YAML-related tests")

    for item in items:
        nid = item.nodeid  # full path::test_name

        if missing_jsonschema:
            # Heuristic: any test with 'validate' in its nodeid exercises schema validation.
            if "validate" in nid:
                item.add_marker(skip_validate)

            # Known 'check' test which invokes validation internally.
            if nid.endswith("test_cli_check_and_strict.py::test_main_returns_code_instead_of_exiting"):
                item.add_marker(skip_validate)

        if missing_yaml:
            # Heuristic: any test with 'yaml' in its nodeid exercises YAML parsing.
            if "yaml" in nid.lower():
                item.add_marker(skip_yaml)
