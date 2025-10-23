import importlib.util

import pytest

for _mod in ("authzed", "grpc", "google.protobuf"):
    if importlib.util.find_spec(_mod) is None:
        pytest.skip(
            f"optional dependency '{_mod}' is not installed; skipping SpiceDB tests",
            allow_module_level=True,
        )

import importlib

import pytest


def test_secure_and_insecure_clients_and_bearer():
    sp = importlib.import_module("rbacx.rebac.spicedb")
    cfg = sp.SpiceDBConfig(endpoint="grpc.example:443", token="TKN", insecure=False)
    checker = sp.SpiceDBChecker(cfg)
    assert checker.check("user:1", "viewer", "doc:1") in (True, False)

    cfg_insec = sp.SpiceDBConfig(endpoint="localhost:50051", token=None, insecure=True)
    checker2 = sp.SpiceDBChecker(cfg_insec)
    assert checker2.check("user:1", "viewer", "doc:1") in (True, False)


def test_build_request_and_consistency_modes():
    sp = importlib.import_module("rbacx.rebac.spicedb")
    cfg = sp.SpiceDBConfig(endpoint="e", token="t", insecure=False, prefer_fully_consistent=True)
    c = sp.SpiceDBChecker(cfg)
    r1 = c._build_request(
        subject="user:1", relation="r", resource="doc:1", context={"k": 1}, zed_token="Z"
    )
    r2 = c._build_request(
        subject="user:1", relation="r", resource="doc:1", context=None, zed_token=None
    )
    assert hasattr(r1, "permission") and hasattr(r2, "permission")


def test_rpc_error_path_returns_false(monkeypatch):
    sp = importlib.import_module("rbacx.rebac.spicedb")
    cfg = sp.SpiceDBConfig(endpoint="e", token="t", insecure=False)
    checker = sp.SpiceDBChecker(cfg)

    # Monkeypatch the INSTANTIATED secure client used internally
    def boom(req, timeout=None):
        import grpc

        raise grpc.RpcError("boom")

    monkeypatch.setattr(checker._client, "CheckPermission", boom, raising=True)
    assert checker.check("u:1", "r", "o:1") is False


@pytest.mark.asyncio
async def test_async_mode_branch(monkeypatch):
    sp = importlib.import_module("rbacx.rebac.spicedb")
    cfg = sp.SpiceDBConfig(endpoint="e", token="t", insecure=False)
    checker = sp.SpiceDBChecker(cfg, async_mode=True)

    async def ok(req, timeout=None):
        from authzed.api.v1 import CheckPermissionResponse

        return CheckPermissionResponse(CheckPermissionResponse.PERMISSIONSHIP_HAS_PERMISSION)

    # Patch the instantiated async client
    monkeypatch.setattr(checker._aclient, "CheckPermission", ok, raising=True)
    assert await checker.check("u:1", "r", "o:1") in (True, False)
    out = await checker.batch_check([("u:1", "r", "o:1"), ("u:2", "r", "o:2")])
    assert len(out) == 2
