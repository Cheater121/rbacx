import asyncio
import inspect
from asyncio import AbstractEventLoop
from typing import Any, Awaitable


async def maybe_await(x: Any) -> Any:
    """Await a value if it's awaitable, otherwise return it as-is."""
    if inspect.isawaitable(x):
        return await x
    return x


async def _await_compat(x: Awaitable[Any]) -> Any:
    """Wrap any awaitable into a coroutine for run_coroutine_threadsafe()."""
    return await x


def resolve_awaitable_in_worker(
    x: Any, loop: AbstractEventLoop, *, timeout: float | None = 5.0
) -> Any:
    """
    Resolve an awaitable from a worker thread by submitting it to the captured loop.
    Falls back to the original value if it's not awaitable.

    Notes:
    - asyncio.run_coroutine_threadsafe() requires a *coroutine object* and returns a Future.
    - We wrap the awaitable with _await_compat(...) to guarantee a coroutine.
    """
    if inspect.isawaitable(x):
        fut = asyncio.run_coroutine_threadsafe(_await_compat(x), loop)
        return fut.result(timeout=timeout)
    return x
