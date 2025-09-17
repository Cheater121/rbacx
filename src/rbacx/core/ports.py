from __future__ import annotations

from typing import Any, Awaitable, Dict, List, Optional, Protocol, Tuple


class DecisionLogSink(Protocol):
    def log(self, payload: Dict[str, Any]) -> None | Awaitable[None]: ...


class ObligationChecker(Protocol):
    def check(
        self, result: Dict[str, Any], context: Any
    ) -> Tuple[bool, Optional[str]] | Awaitable[Tuple[bool, Optional[str]]]: ...


class MetricsSink(Protocol):
    def inc(self, name: str, labels: Dict[str, str] | None = None) -> None | Awaitable[None]: ...


class PolicySource(Protocol):
    def load(self) -> Dict[str, Any] | Awaitable[Dict[str, Any]]: ...
    def etag(self) -> Optional[str] | Awaitable[Optional[str]]: ...


class RoleResolver(Protocol):
    def expand(self, roles: List[str] | None) -> List[str] | Awaitable[List[str]]:
        """Return roles including inherited/derived ones."""


# Optional extension: sinks MAY implement observe() for histograms (adapters will check via hasattr).
class MetricsObserve(Protocol):
    def observe(
        self, name: str, value: float, labels: Dict[str, str] | None = None
    ) -> None | Awaitable[None]: ...
