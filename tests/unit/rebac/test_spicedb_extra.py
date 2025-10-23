import importlib.util

import pytest

for _mod in ("authzed", "grpc", "google.protobuf"):
    if importlib.util.find_spec(_mod) is None:
        pytest.skip(
            f"optional dependency '{_mod}' is not installed; skipping SpiceDB tests",
            allow_module_level=True,
        )

import importlib


def test_build_request_with_nested_context_and_zed_token():
    sp = importlib.import_module("rbacx.rebac.spicedb")
    cfg = sp.SpiceDBConfig(endpoint="e", token="t", insecure=False)
    c = sp.SpiceDBChecker(cfg)
    ctx = {"a": 1, "b": {"c": [1, 2, {"d": True}], "e": None}}
    req = c._build_request(
        subject="user:1", relation="view", resource="doc:9", context=ctx, zed_token="XYZ"
    )
    assert req.permission == "view" and hasattr(req, "consistency") and req.context is not None
    assert c.check("user:1", "view", "doc:9", context=ctx, zed_token="XYZ") in (True, False)
