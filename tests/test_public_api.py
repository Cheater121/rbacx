import importlib


def test_public_api_imports():
    # Public imports guaranteed stable starting from 1.0.0
    names = [
        "Guard",
        "Subject",
        "Action",
        "Resource",
        "Context",
        "Decision",
        "HotReloader",
        "load_policy",
        "core",
        "adapters",
        "storage",
        "obligations",
        "__version__",
    ]
    mod = importlib.import_module("rbacx")
    for n in names:
        assert hasattr(mod, n), f"Missing public import: rbacx.{n}"
