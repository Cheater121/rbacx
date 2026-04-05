"""Unit tests for SpiceDB native BulkCheckPermissions batch_check."""

import importlib
import importlib.util
from unittest.mock import MagicMock

import pytest

for _mod in ("authzed", "grpc", "google.protobuf"):
    if importlib.util.find_spec(_mod) is None:
        pytest.skip(
            f"optional dependency '{_mod}' not installed; skipping SpiceDB tests",
            allow_module_level=True,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_pair(permissionship):
    """Build a minimal BulkCheckPermissionPair-like object."""
    pair = MagicMock()
    pair.item.permissionship = permissionship
    return pair


def _has_permission():
    from authzed.api.v1 import CheckPermissionResponse

    return CheckPermissionResponse.PERMISSIONSHIP_HAS_PERMISSION


def _no_permission():
    from authzed.api.v1 import CheckPermissionResponse

    return CheckPermissionResponse.PERMISSIONSHIP_NO_PERMISSION


# ---------------------------------------------------------------------------
# Empty triples — early return
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_batch_check_empty_returns_empty():
    sp = importlib.import_module("rbacx.rebac.spicedb")
    cfg = sp.SpiceDBConfig(endpoint="e", token="t", insecure=False)
    checker = sp.SpiceDBChecker(cfg, async_mode=True)
    # batch_check([]) returns [] immediately (not a coroutine) even in async mode
    result = checker.batch_check([])
    assert result == []


def test_batch_check_sync_empty_returns_empty():
    sp = importlib.import_module("rbacx.rebac.spicedb")
    cfg = sp.SpiceDBConfig(endpoint="localhost:50051", token=None, insecure=True)
    checker = sp.SpiceDBChecker(cfg)
    result = checker.batch_check([])
    assert result == []


# ---------------------------------------------------------------------------
# Async mode — uses BulkCheckPermissions
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_batch_check_async_native_bulk(monkeypatch):
    """async batch_check calls BulkCheckPermissions once (not N CheckPermissions)."""
    sp = importlib.import_module("rbacx.rebac.spicedb")
    cfg = sp.SpiceDBConfig(endpoint="e", token="t", insecure=False)
    checker = sp.SpiceDBChecker(cfg, async_mode=True)

    bulk_calls: list = []

    async def fake_bulk(req, timeout=None):
        bulk_calls.append(req)
        resp = MagicMock()
        resp.pairs = [_make_pair(_has_permission()), _make_pair(_no_permission())]
        return resp

    # Attach BulkCheckPermissions to the client (may not exist on older authzed)
    checker._aclient.BulkCheckPermissions = fake_bulk

    triples = [("user:1", "viewer", "doc:1"), ("user:2", "viewer", "doc:2")]
    result = await checker.batch_check(triples)

    assert len(bulk_calls) == 1  # single gRPC call
    assert result == [True, False]


@pytest.mark.asyncio
async def test_batch_check_async_rpc_error_returns_falses(monkeypatch):
    """RPC error on BulkCheckPermissions returns [False] * N."""
    sp = importlib.import_module("rbacx.rebac.spicedb")
    import grpc

    cfg = sp.SpiceDBConfig(endpoint="e", token="t", insecure=False)
    checker = sp.SpiceDBChecker(cfg, async_mode=True)

    async def boom(req, timeout=None):
        raise grpc.RpcError("network failure")

    checker._aclient.BulkCheckPermissions = boom

    triples = [("u:1", "r", "o:1"), ("u:2", "r", "o:2"), ("u:3", "r", "o:3")]
    result = await checker.batch_check(triples)
    assert result == [False, False, False]


# ---------------------------------------------------------------------------
# Sync mode — sequential fallback (no bulk endpoint on sync client)
# ---------------------------------------------------------------------------


def test_batch_check_sync_sequential_fallback(monkeypatch):
    """sync batch_check falls back to sequential CheckPermission calls."""
    sp = importlib.import_module("rbacx.rebac.spicedb")
    from authzed.api.v1 import CheckPermissionResponse

    cfg = sp.SpiceDBConfig(endpoint="localhost:50051", token=None, insecure=True)
    checker = sp.SpiceDBChecker(cfg)

    call_count = [0]

    def fake_check(req, timeout=None):
        call_count[0] += 1
        r = CheckPermissionResponse()
        r.permissionship = CheckPermissionResponse.PERMISSIONSHIP_HAS_PERMISSION
        return r

    monkeypatch.setattr(checker._client, "CheckPermission", fake_check, raising=True)

    triples = [("u:1", "r", "o:1"), ("u:2", "r", "o:2")]
    result = checker.batch_check(triples)

    assert call_count[0] == 2  # two separate calls
    assert result == [True, True]


# ---------------------------------------------------------------------------
# Coverage: zed_token, prefer_fully_consistent, except Exception in BulkCheck
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_batch_check_async_with_zed_token(monkeypatch):
    """zed_token is forwarded to BulkCheckPermissions consistency field (line 197)."""
    sp = importlib.import_module("rbacx.rebac.spicedb")
    cfg = sp.SpiceDBConfig(endpoint="e", token="t", insecure=False)
    checker = sp.SpiceDBChecker(cfg, async_mode=True)

    captured_req = []

    async def fake_bulk(req, timeout=None):
        captured_req.append(req)
        resp = MagicMock()
        resp.pairs = [_make_pair(_has_permission())]
        return resp

    checker._aclient.BulkCheckPermissions = fake_bulk

    await checker.batch_check([("user:1", "viewer", "doc:1")], zed_token="Z123")
    assert len(captured_req) == 1
    # Consistency must be set (not None)
    assert captured_req[0].consistency is not None


@pytest.mark.asyncio
async def test_batch_check_async_prefer_fully_consistent(monkeypatch):
    """prefer_fully_consistent=True sets consistency on the bulk request (line 201)."""
    sp = importlib.import_module("rbacx.rebac.spicedb")
    cfg = sp.SpiceDBConfig(endpoint="e", token="t", insecure=False, prefer_fully_consistent=True)
    checker = sp.SpiceDBChecker(cfg, async_mode=True)

    captured_req = []

    async def fake_bulk(req, timeout=None):
        captured_req.append(req)
        resp = MagicMock()
        resp.pairs = [_make_pair(_no_permission())]
        return resp

    checker._aclient.BulkCheckPermissions = fake_bulk

    await checker.batch_check([("user:1", "viewer", "doc:1")])
    assert captured_req[0].consistency is not None


@pytest.mark.asyncio
async def test_batch_check_async_unexpected_exception_returns_falses(monkeypatch):
    """Generic Exception in BulkCheckPermissions returns [False]*N (lines 258-262)."""
    sp = importlib.import_module("rbacx.rebac.spicedb")
    cfg = sp.SpiceDBConfig(endpoint="e", token="t", insecure=False)
    checker = sp.SpiceDBChecker(cfg, async_mode=True)

    async def boom(req, timeout=None):
        raise ValueError("unexpected error")

    checker._aclient.BulkCheckPermissions = boom

    triples = [("u:1", "r", "o:1"), ("u:2", "r", "o:2")]
    result = await checker.batch_check(triples)
    assert result == [False, False]
