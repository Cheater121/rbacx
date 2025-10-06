class StaticRoleResolver:
    """Simple in-memory role resolver with inheritance.

    graph: {role: [parent_role, ...]}
    expand(['manager']) -> ['manager', 'employee', 'user', ...]
    """

    def __init__(self, graph: dict[str, list[str]] | None = None) -> None:
        self.graph = graph or {}

    def expand(self, roles: list[str] | None) -> list[str]:
        if not roles:
            return []
        out: set[str] = set()
        stack = list(roles)
        while stack:
            r = stack.pop()
            if r in out:
                continue
            out.add(r)
            for p in self.graph.get(r, []):
                stack.append(p)
        return sorted(out)
