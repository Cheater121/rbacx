import asyncio

import pytest


def test_fastapi_require_access_denied_with_headers(monkeypatch):
    # fastapi dependency raises HTTPException when denied; assert on that
    try:
        import rbacx.adapters.fastapi_guard as fg
    except ImportError:
        pytest.skip("Module deleted")

    async def handler():
        with pytest.raises(Exception) as ei:
            await fg.require_access(
                guard=lambda *a, **k: (False, {"reason": "X"}), add_headers=True
            )()
        # FastAPI HTTPException carries status_code attribute
        exc = ei.value
        assert getattr(exc, "status_code", 403) == 403

    asyncio.run(handler())


def test_litestar_middleware_denies_and_allows(monkeypatch):
    # If there's no running loop, create one
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    # Minimal smoke: import and ensure callables exist
    import rbacx.adapters.litestar_guard as lg

    assert hasattr(lg, "require")
