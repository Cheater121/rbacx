
from __future__ import annotations

from typing import Dict, List, Set


class StaticRoleResolver:
    """Simple in-memory role resolver with inheritance.

    graph: {role: [parent_role, ...]}
    expand(['manager']) -> ['manager', 'employee', 'user', ...]
    """
    def __init__(self, graph: Dict[str, List[str]] | None = None) -> None:
        self.graph = graph or {}

    def expand(self, roles: List[str] | None) -> List[str]:
        if not roles:
            return []
        out: Set[str] = set()
        stack = list(roles)
        while stack:
            r = stack.pop()
            if r in out:
                continue
            out.add(r)
            for p in self.graph.get(r, []):
                stack.append(p)
        return sorted(out)
