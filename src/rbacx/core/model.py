from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class Subject:
    id: str
    roles: list[str] = field(default_factory=list)
    attrs: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Resource:
    type: str
    id: str | None = None
    attrs: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Action:
    name: str


@dataclass(frozen=True, slots=True)
class Context:
    attrs: dict[str, Any] = field(default_factory=dict)
