import importlib
import importlib.util
import sys
import types
from contextlib import contextmanager

import pytest

if importlib.util.find_spec("httpx") is None:
    pytest.skip(
        "optional dependency 'httpx' is not installed; skipping OpenFGA tests",
        allow_module_level=True,
    )


class _Resp:
    def __init__(self, payload, http_error=False):
        self._payload = payload
        self._http_error = http_error

    def raise_for_status(self):
        if self._http_error:
            raise HTTPError("boom")

    def json(self):
        return self._payload


class HTTPError(Exception): ...


def make_httpx(
    *, payload=None, raise_http=False, async_payload=None, async_raise_http=False, echo_body=False
):
    """Stub 'httpx' module with Client and AsyncClient."""

    def _post(url, *, json=None, headers=None, timeout=None):
        if raise_http:
            return _Resp(None, http_error=True)
        return _Resp(payload if not echo_body else (json or {}), http_error=False)

    async def _apost(url, *, json=None, headers=None, timeout=None):
        if async_raise_http:
            raise HTTPError("async boom")
        return _Resp(
            async_payload if async_payload is not None else (json if echo_body else payload)
        )

    class Client:
        def __init__(self, timeout=None):
            self.timeout = timeout
            self._last = None

        def post(self, url, *, json=None, headers=None, timeout=None):
            self._last = (url, json, headers, timeout)
            return _post(url, json=json, headers=headers, timeout=timeout)

    class AsyncClient:
        def __init__(self, timeout=None):
            self.timeout = timeout
            self._last = None

        async def post(self, url, *, json=None, headers=None, timeout=None):
            self._last = (url, json, headers, timeout)
            return await _apost(url, json=json, headers=headers, timeout=timeout)

    mod = types.ModuleType("httpx")
    mod.Client = Client
    mod.AsyncClient = AsyncClient
    mod.HTTPError = HTTPError
    return mod


@contextmanager
def stub_httpx(mod):
    old = sys.modules.get("httpx")
    sys.modules["httpx"] = mod
    try:
        ofga = importlib.reload(importlib.import_module("rbacx.rebac.openfga"))
        yield ofga
    finally:
        if old is None:
            sys.modules.pop("httpx", None)
        else:
            sys.modules["httpx"] = old
        importlib.reload(importlib.import_module("rbacx.rebac.openfga"))


def test_init_raises_when_httpx_missing():
    ofga = importlib.import_module("rbacx.rebac.openfga")
    saved = ofga.httpx
    try:
        ofga.httpx = None
        with pytest.raises(RuntimeError):
            ofga.OpenFGAChecker(ofga.OpenFGAConfig(api_url="http://api", store_id="s"))
    finally:
        ofga.httpx = saved


def test_default_sync_client_created_and_used():
    with stub_httpx(make_httpx(payload={"allowed": True})) as ofga:
        cfg = ofga.OpenFGAConfig(api_url="http://api", store_id="store", api_token="tk")
        cli = ofga.OpenFGAChecker(cfg)
        assert isinstance(cli._client, ofga.httpx.Client)  # type: ignore[attr-defined]
        assert cli.check("u", "r", "o") is True


def test_check_includes_context_and_headers_and_urls():
    with stub_httpx(make_httpx(echo_body=True)) as ofga:
        cfg = ofga.OpenFGAConfig(
            api_url="http://api/", store_id="S", api_token="TKN", authorization_model_id="M"
        )
        cli = ofga.OpenFGAChecker(cfg, client=ofga.httpx.Client())  # type: ignore[attr-defined]
        res = cli.check("user:1", "viewer", "obj:1", context={"ip": "1.2.3.4"})
        assert isinstance(res, bool)
        url, body, headers, timeout = cli._client._last  # type: ignore[attr-defined]
        assert url.endswith("/stores/S/check")
        assert headers.get("authorization") == "Bearer TKN"
        assert headers.get("content-type") == "application/json"
        assert body.get("context") == {"ip": "1.2.3.4"}
        assert body.get("authorization_model_id") == "M"


@pytest.mark.asyncio
async def test_async_guard_raises_if_client_missing_at_call_time():
    with stub_httpx(make_httpx(async_payload={"allowed": True})) as ofga:
        cfg = ofga.OpenFGAConfig(api_url="http://api", store_id="s")
        cli = ofga.OpenFGAChecker(cfg, async_client=ofga.httpx.AsyncClient())  # type: ignore[attr-defined]
        coro = cli.check("u", "r", "o")
        cli._aclient = None
        with pytest.raises(RuntimeError):
            await coro


@pytest.mark.asyncio
async def test_async_check_http_error_logs_and_returns_false(caplog):
    with stub_httpx(make_httpx(async_raise_http=True)) as ofga:
        cfg = ofga.OpenFGAConfig(api_url="http://api", store_id="s")
        cli = ofga.OpenFGAChecker(cfg, async_client=ofga.httpx.AsyncClient())  # type: ignore[attr-defined]
        caplog.set_level("WARNING")
        out = await cli.check("u", "r", "o")
        assert out is False
        assert any("OpenFGA async check HTTP error" in r.message for r in caplog.records)


def test_sync_guard_raises_if_client_missing():
    with stub_httpx(make_httpx()) as ofga:
        cfg = ofga.OpenFGAConfig(api_url="http://api", store_id="s")
        cli = ofga.OpenFGAChecker(cfg, client=ofga.httpx.Client())  # type: ignore[attr-defined]
        cli._client = None
        with pytest.raises(RuntimeError):
            cli.check("u", "r", "o")


def test_sync_check_http_error_logs_and_returns_false(caplog):
    with stub_httpx(make_httpx(raise_http=True)) as ofga:
        cfg = ofga.OpenFGAConfig(api_url="http://api", store_id="s")
        cli = ofga.OpenFGAChecker(cfg, client=ofga.httpx.Client())  # type: ignore[attr-defined]
        caplog.set_level("WARNING")
        out = cli.check("u", "r", "o")
        assert out is False
        assert any("OpenFGA check HTTP error" in r.message for r in caplog.records)


def test_batch_check_includes_context_and_model_id():
    with stub_httpx(make_httpx(echo_body=True)) as ofga:
        cfg = ofga.OpenFGAConfig(api_url="http://api", store_id="s", authorization_model_id="M")
        cli = ofga.OpenFGAChecker(cfg, client=ofga.httpx.Client())  # type: ignore[attr-defined]
        out = cli.batch_check([("u1", "r", "o1"), ("u2", "r", "o2")], context={"x": 1})
        assert isinstance(out, list)
        url, body, headers, timeout = cli._client._last  # type: ignore[attr-defined]
        assert url.endswith("/stores/s/batch-check")
        assert body.get("context") == {"x": 1}
        assert body.get("authorization_model_id") == "M"


@pytest.mark.asyncio
async def test_async_batch_guard_raises_if_client_missing():
    with stub_httpx(make_httpx(async_payload={"results": {}})) as ofga:
        cfg = ofga.OpenFGAConfig(api_url="http://api", store_id="s")
        cli = ofga.OpenFGAChecker(cfg, async_client=ofga.httpx.AsyncClient())  # type: ignore[attr-defined]
        coro = cli.batch_check([("u1", "r", "o1")])
        cli._aclient = None
        with pytest.raises(RuntimeError):
            await coro


@pytest.mark.asyncio
async def test_async_batch_results_map_shape_is_respected(monkeypatch):
    import uuid as _uuid

    seq = ["c1", "c2"]
    it = iter(seq)
    monkeypatch.setattr(_uuid, "uuid4", lambda: next(it))
    with stub_httpx(
        make_httpx(async_payload={"results": {"c1": {"allowed": True}, "c2": {"allowed": False}}})
    ) as ofga:
        cfg = ofga.OpenFGAConfig(api_url="http://api", store_id="s")
        cli = ofga.OpenFGAChecker(cfg, async_client=ofga.httpx.AsyncClient())  # type: ignore[attr-defined]
        out = await cli.batch_check([("u1", "r", "o1"), ("u2", "r", "o2")])
        assert out == [True, False]


@pytest.mark.asyncio
async def test_async_batch_unrecognized_shape_returns_falses():
    with stub_httpx(make_httpx(async_payload={"weird": 1})) as ofga:
        cfg = ofga.OpenFGAConfig(api_url="http://api", store_id="s")
        cli = ofga.OpenFGAChecker(cfg, async_client=ofga.httpx.AsyncClient())  # type: ignore[attr-defined]
        out = await cli.batch_check([("u1", "r", "o1"), ("u2", "r", "o2"), ("u3", "r", "o3")])
        assert out == [False, False, False]


def test_sync_batch_guard_raises_if_client_missing():
    with stub_httpx(make_httpx(payload={"results": {}})) as ofga:
        cfg = ofga.OpenFGAConfig(api_url="http://api", store_id="s")
        cli = ofga.OpenFGAChecker(cfg, client=ofga.httpx.Client())  # type: ignore[attr-defined]
        cli._client = None
        with pytest.raises(RuntimeError):
            cli.batch_check([("u", "r", "o")])


def test_sync_batch_result_list_shape(monkeypatch):
    import uuid as _uuid

    seq = ["c1", "c2", "c3"]
    it = iter(seq)
    monkeypatch.setattr(_uuid, "uuid4", lambda: next(it))
    items = [
        {"correlationId": "c1", "allowed": True},
        {"correlationId": "c2", "allowed": False},
        {"correlationId": "c3", "allowed": True},
    ]
    with stub_httpx(make_httpx(payload={"result": items})) as ofga:
        cfg = ofga.OpenFGAConfig(api_url="http://api", store_id="s")
        cli = ofga.OpenFGAChecker(cfg, client=ofga.httpx.Client())  # type: ignore[attr-defined]
        out = cli.batch_check([("u1", "r", "o1"), ("u2", "r", "o2"), ("u3", "r", "o3")])
        assert out == [True, False, True]


def test_sync_batch_http_error_logs_and_returns_falses(caplog):
    with stub_httpx(make_httpx(raise_http=True)) as ofga:
        cfg = ofga.OpenFGAConfig(api_url="http://api", store_id="s")
        cli = ofga.OpenFGAChecker(cfg, client=ofga.httpx.Client())  # type: ignore[attr-defined]
        caplog.set_level("WARNING")
        out = cli.batch_check([("u1", "r", "o1"), ("u2", "r", "o2"), ("u3", "r", "o3")])
        assert out == [False, False, False]
        assert any("OpenFGA batch-check HTTP error" in r.message for r in caplog.records)
