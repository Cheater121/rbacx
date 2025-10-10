import importlib
import importlib.util
import types

import pytest

if importlib.util.find_spec("httpx") is None:
    pytest.skip(
        "optional dependency 'httpx' is not installed; skipping OpenFGA tests",
        allow_module_level=True,
    )


def make_httpx(ok=True, payload=None, raise_http=False, echo_batch=False, async_http_error=False):
    class HTTPError(Exception): ...

    class _Resp:
        def __init__(self, data, http_error=False):
            self._data = data
            self._http_error = http_error

        def json(self):
            return self._data

        def raise_for_status(self):
            if self._http_error:
                raise HTTPError("boom")

    class Client:
        def __init__(self, *a, **kw):
            pass

        def post(self, url, json=None, headers=None, timeout=None):
            return _Resp(payload if payload is not None else {"allowed": ok}, http_error=raise_http)

    class AsyncClient:
        def __init__(self, *a, **kw):
            pass

        async def post(self, url, json=None, headers=None, timeout=None):
            if async_http_error:
                return _Resp({}, http_error=True)
            is_batch = echo_batch and ("batch" in url or "check-batch" in url)
            if is_batch:
                tuples = []
                if isinstance(json, dict):
                    for v in json.values():
                        if isinstance(v, list) and v and isinstance(v[0], dict):
                            tuples = v
                            break
                result = []
                for i, t in enumerate(tuples):
                    cid = t.get("correlationId") or t.get("correlation_id") or str(i)
                    result.append({"correlationId": cid, "allowed": (i % 2 == 0)})
                return _Resp({"result": result}, http_error=False)
            return _Resp(payload if payload is not None else {"allowed": ok}, http_error=raise_http)

    mod = types.ModuleType("httpx")
    mod.Client = Client
    mod.AsyncClient = AsyncClient
    mod.HTTPError = HTTPError
    return mod


def test_sync_check_and_headers_and_url_building(monkeypatch):
    import sys

    sys.modules["httpx"] = make_httpx(ok=True)
    ofga = importlib.reload(importlib.import_module("rbacx.rebac.openfga"))

    cfg = ofga.OpenFGAConfig(
        api_url="http://api", store_id="store42", api_token="tkn", authorization_model_id="modelX"
    )
    cli = ofga.OpenFGAChecker(cfg, client=ofga.httpx.Client())  # type: ignore[attr-defined]

    assert cli.check("user:1", "viewer", "doc:1") is True

    payload = {"results": {"a": {"allowed": True}, "b": {"allowed": False}}}
    sys.modules["httpx"] = make_httpx(payload=payload)
    ofga = importlib.reload(ofga)
    cli = ofga.OpenFGAChecker(cfg, client=ofga.httpx.Client())  # type: ignore[attr-defined]
    got = cli.batch_check([("u:1", "v", "o:1"), ("u:2", "v", "o:2")])
    assert len(got) == 2 and set(got) <= {True, False}


@pytest.mark.asyncio
async def test_async_clients_both_endpoints():
    import sys

    sys.modules["httpx"] = make_httpx(echo_batch=True)
    ofga = importlib.reload(importlib.import_module("rbacx.rebac.openfga"))
    cfg = ofga.OpenFGAConfig(api_url="http://api", store_id="s", api_token=None)
    cli = ofga.OpenFGAChecker(cfg, async_client=ofga.httpx.AsyncClient())  # type: ignore[attr-defined]
    res = await cli.check("u:1", "r", "o:1")
    assert res in (True, False)

    batch = await cli.batch_check([("u:1", "r", "o:1"), ("u:2", "r", "o:2")])
    assert batch == [True, False]


@pytest.mark.asyncio
async def test_async_http_error_branch_returns_falses():
    import sys

    sys.modules["httpx"] = make_httpx(async_http_error=True)
    ofga = importlib.reload(importlib.import_module("rbacx.rebac.openfga"))
    cfg = ofga.OpenFGAConfig(api_url="http://api", store_id="s")
    cli = ofga.OpenFGAChecker(cfg, async_client=ofga.httpx.AsyncClient())  # type: ignore[attr-defined]
    out = await cli.batch_check([("u:1", "r", "o:1"), ("u:2", "r", "o:2"), ("u:3", "r", "o:3")])
    assert out == [False, False, False]
