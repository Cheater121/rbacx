import importlib
import importlib.util
import types
from dataclasses import dataclass

import pytest

# Skip the whole module if optional dependencies aren't installed.
# We do NOT fake-install them here on purpose: project policy says to skip.
if importlib.util.find_spec("authzed") is None or importlib.util.find_spec("grpc") is None:
    pytest.skip(
        "optional dependencies 'authzed'/'grpc' are not installed; skipping SpiceDB tests",
        allow_module_level=True,
    )


# Small response holder used by our stubs
@dataclass
class _Resp:
    permissionship: int


def _load_mod():
    """Import rbacx.rebac.spicedb fresh each time."""
    # Ensure src/ is on sys.path if your test runner doesn't add it.
    # from pathlib import Path
    # sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "src"))
    return importlib.import_module("rbacx.rebac.spicedb")


def test_init_raises_when_authzed_missing():
    """
    Covers lines 79–82: __init__ should raise when ZedClient is None.
    We simulate "optional deps missing" by nulling ZedClient on the module.
    """
    sp = _load_mod()
    saved = sp.ZedClient
    try:
        sp.ZedClient = None  # simulate import failure branch
        with pytest.raises(RuntimeError):
            sp.SpiceDBChecker(sp.SpiceDBConfig(endpoint="localhost:50051"))
    finally:
        sp.ZedClient = saved


def test_sync_check_success_and_headers_via_insecure_stub(monkeypatch):
    """
    Covers line 155 (sync true-branch) by stubbing ZedInsecureClient to a
    minimal client that returns HAS_PERMISSION.
    """
    sp = _load_mod()
    # Provide a fake enum container to be robust to client versions
    sp.CheckPermissionResponse = types.SimpleNamespace(
        PERMISSIONSHIP_HAS_PERMISSION=1, PERMISSIONSHIP_NO_PERMISSION=0
    )

    class _ClientStub:
        def __init__(self, endpoint, token):
            self.endpoint, self.token = endpoint, token

        def CheckPermission(self, request, timeout=None):
            # Always return HAS_PERMISSION
            return _Resp(sp.CheckPermissionResponse.PERMISSIONSHIP_HAS_PERMISSION)

    monkeypatch.setattr(sp, "ZedInsecureClient", _ClientStub)
    cfg = sp.SpiceDBConfig(endpoint="localhost:50051", token="tkn", insecure=True)
    cli = sp.SpiceDBChecker(cfg)  # uses our insecure stub
    assert cli.check("user:1", "viewer", "post:1") is True  # line 155


def test_sync_guard_raises_when_no_client():
    """
    Covers line 151: sync check must raise if _client is None.
    """
    sp = _load_mod()

    class _ClientStub:
        def __init__(self, endpoint, token): ...

        def CheckPermission(self, request, timeout=None):
            return _Resp(sp.CheckPermissionResponse.PERMISSIONSHIP_NO_PERMISSION)

    sp.CheckPermissionResponse = types.SimpleNamespace(
        PERMISSIONSHIP_HAS_PERMISSION=1, PERMISSIONSHIP_NO_PERMISSION=0
    )

    # Ensure constructor succeeds, then remove the client
    cli = sp.SpiceDBChecker(sp.SpiceDBConfig(endpoint="localhost:50051", insecure=True))
    cli._client = None  # force the guard
    with pytest.raises(RuntimeError):
        cli.check("user:1", "viewer", "post:1")  # line 151


def test_batch_sync_fallback_list_comprehension(monkeypatch):
    """
    Covers line 185: sync fallback builds a list via list-comprehension of check().
    We alternate True/False responses to verify order and length.
    """
    sp = _load_mod()
    sp.CheckPermissionResponse = types.SimpleNamespace(
        PERMISSIONSHIP_HAS_PERMISSION=1, PERMISSIONSHIP_NO_PERMISSION=0
    )

    class _ClientStub:
        def __init__(self, endpoint, token):
            self.i = 0

        def CheckPermission(self, request, timeout=None):
            # Alternate True / False
            self.i += 1
            val = (
                sp.CheckPermissionResponse.PERMISSIONSHIP_HAS_PERMISSION
                if self.i % 2 == 1
                else sp.CheckPermissionResponse.PERMISSIONSHIP_NO_PERMISSION
            )
            return _Resp(val)

    monkeypatch.setattr(sp, "ZedInsecureClient", _ClientStub)
    cli = sp.SpiceDBChecker(sp.SpiceDBConfig(endpoint="localhost:50051", insecure=True))
    triples = [("u1", "r", "o1"), ("u2", "r", "o2"), ("u3", "r", "o3"), ("u4", "r", "o4")]
    out = cli.batch_check(triples)  # line 185
    assert out == [True, False, True, False]


@pytest.mark.asyncio
async def test_async_check_success(monkeypatch):
    """
    Covers lines 138–140: async check returns True when permissionship == HAS_PERMISSION.
    We set _aclient manually to avoid relying on specific client symbols.
    """
    sp = _load_mod()
    sp.CheckPermissionResponse = types.SimpleNamespace(
        PERMISSIONSHIP_HAS_PERMISSION=1, PERMISSIONSHIP_NO_PERMISSION=0
    )

    class _AsyncStub:
        async def CheckPermission(self, request, timeout=None):
            return _Resp(sp.CheckPermissionResponse.PERMISSIONSHIP_HAS_PERMISSION)

    cli = sp.SpiceDBChecker(sp.SpiceDBConfig(endpoint="localhost:50051", insecure=True))
    cli._aclient = _AsyncStub()  # prefer async path
    res = await cli.check("user:1", "viewer", "post:1")  # lines 138–140
    assert res is True


@pytest.mark.asyncio
async def test_async_check_rpcerror_logs_and_returns_false(monkeypatch, caplog):
    """
    Covers lines 142–143: catching RpcError in async check returns False and logs warning.
    """
    sp = _load_mod()

    class _RpcErr(Exception): ...

    sp.RpcError = _RpcErr  # patch RpcError used in module

    class _AsyncStub:
        async def CheckPermission(self, request, timeout=None):
            raise _RpcErr("boom")

    cli = sp.SpiceDBChecker(sp.SpiceDBConfig(endpoint="localhost:50051", insecure=True))
    cli._aclient = _AsyncStub()
    caplog.set_level("WARNING")
    out = await cli.check("user:1", "viewer", "post:1")  # lines 142–143
    assert out is False
    assert any("SpiceDB async check RPC error" in r.message for r in caplog.records)


@pytest.mark.asyncio
async def test_check_single_async_guard_raises_when_no_async_client():
    """
    Covers line 249: _check_single_async must raise when _aclient is None.
    """
    sp = _load_mod()
    cli = sp.SpiceDBChecker(sp.SpiceDBConfig(endpoint="localhost:50051", insecure=True))
    cli._aclient = None  # explicit
    with pytest.raises(RuntimeError):
        await cli._check_single_async("u", "r", "o")  # line 249


@pytest.mark.asyncio
async def test_check_single_async_success_and_rpcerror(monkeypatch, caplog):
    """
    Covers lines 259 and 261–262: success path and RpcError handling in _check_single_async.
    """
    sp = _load_mod()
    sp.CheckPermissionResponse = types.SimpleNamespace(
        PERMISSIONSHIP_HAS_PERMISSION=1, PERMISSIONSHIP_NO_PERMISSION=0
    )

    class _RpcErr(Exception): ...

    sp.RpcError = _RpcErr  # patch RpcError type used in except

    class _AsyncOK:
        async def CheckPermission(self, request, timeout=None):
            return _Resp(sp.CheckPermissionResponse.PERMISSIONSHIP_HAS_PERMISSION)

    class _AsyncFail:
        async def CheckPermission(self, request, timeout=None):
            raise _RpcErr("rpc down")

    cli = sp.SpiceDBChecker(sp.SpiceDBConfig(endpoint="localhost:50051", insecure=True))

    # Success branch (line 259)
    cli._aclient = _AsyncOK()
    ok = await cli._check_single_async("u", "r", "o")
    assert ok is True

    # RpcError branch (lines 261–262)
    cli._aclient = _AsyncFail()
    caplog.set_level("WARNING")
    bad = await cli._check_single_async("u", "r", "o")
    assert bad is False
    assert any("SpiceDB async check RPC error" in r.message for r in caplog.records)
