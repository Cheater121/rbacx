
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass(frozen=True, slots=True)
class Subject:
    id: str
    roles: List[str] = field(default_factory=list)
    attrs: Dict[str, Any] = field(default_factory=dict)

@dataclass(frozen=True, slots=True)
class Resource:
    type: str
    id: Optional[str] = None
    attrs: Dict[str, Any] = field(default_factory=dict)

@dataclass(frozen=True, slots=True)
class Action:
    name: str

@dataclass(frozen=True, slots=True)
class Context:
    attrs: Dict[str, Any] = field(default_factory=dict)
