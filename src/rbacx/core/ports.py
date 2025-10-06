from collections.abc import Awaitable
from typing import Any, Protocol


class DecisionLogSink(Protocol):
    def log(self, payload: dict[str, Any]) -> None | Awaitable[None]: ...


class ObligationChecker(Protocol):
    def check(
        self, result: dict[str, Any], context: Any
    ) -> tuple[bool, str | None] | Awaitable[tuple[bool, str | None]]: ...


class MetricsSink(Protocol):
    def inc(self, name: str, labels: dict[str, str] | None = None) -> None | Awaitable[None]: ...


class PolicySource(Protocol):
    def load(self) -> dict[str, Any] | Awaitable[dict[str, Any]]: ...
    def etag(self) -> str | None | Awaitable[str | None]: ...


class RoleResolver(Protocol):
    def expand(self, roles: list[str] | None) -> list[str] | Awaitable[list[str]]:
        """Return roles including inherited/derived ones."""


# Optional extension: sinks MAY implement observe() for histograms (adapters will check via hasattr).
class MetricsObserve(Protocol):
    def observe(
        self, name: str, value: float, labels: dict[str, str] | None = None
    ) -> None | Awaitable[None]: ...
