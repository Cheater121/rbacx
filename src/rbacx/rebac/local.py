import logging
import time
from dataclasses import dataclass
from typing import Any, Callable, Iterable

from ..core.ports import RelationshipChecker

logger = logging.getLogger("rbacx.rebac.local")

# ---------------------------
# Userset rewrite primitives
# ---------------------------


@dataclass(frozen=True)
class This:
    """Direct relation: subject --relation--> resource (aka 'this')."""

    pass


@dataclass(frozen=True)
class ComputedUserset:
    """Follow another relation on the SAME object."""

    relation: str


@dataclass(frozen=True)
class TupleToUserset:
    """
    Traverse an object->object edge first (tupleset) and then evaluate a
    relation ('computed_userset') on the TARGET object.
    """

    tupleset: str
    computed_userset: str


# list[...] is treated as a union of userset expressions
UsersetExpr = This | ComputedUserset | TupleToUserset | list["UsersetExpr"]


# ---------------------------
# Tuple store (in-memory)
# ---------------------------


@dataclass(frozen=True)
class RelTuple:
    subject: str  # e.g. "user:42" or "folder:10" (for object->object edges)
    relation: str  # e.g. "viewer", "parent"
    resource: str  # e.g. "document:doc1"
    caveat: str | None = None  # optional caveat name from registry


class InMemoryRelationshipStore:
    """
    Minimal tuple store with indexes by (resource, relation) and (subject, relation).
    Suitable for tests/dev. For production, implement the same interface on top of a DB.
    """

    def __init__(self) -> None:
        self._by_res_rel: dict[tuple[str, str], list[RelTuple]] = {}
        self._by_subj_rel: dict[tuple[str, str], list[RelTuple]] = {}

    def add(self, subject: str, relation: str, resource: str, *, caveat: str | None = None) -> None:
        t = RelTuple(subject=subject, relation=relation, resource=resource, caveat=caveat)
        self._by_res_rel.setdefault((resource, relation), []).append(t)
        self._by_subj_rel.setdefault((subject, relation), []).append(t)

    def direct_for_resource(self, relation: str, resource: str) -> Iterable[RelTuple]:
        return self._by_res_rel.get((resource, relation), ())

    def by_subject(self, subject: str, relation: str) -> Iterable[RelTuple]:
        return self._by_subj_rel.get((subject, relation), ())


# ---------------------------
# LocalRelationshipChecker
# ---------------------------


def _split_ref(ref: str) -> tuple[str, str]:
    """
    Split 'type:id' into ('type', 'id'). If ':' is missing, default type is 'user'.
    """
    if ":" in ref:
        t, _, i = ref.partition(":")
        return t, i
    return "user", ref


class LocalRelationshipChecker(RelationshipChecker):
    """
    In-process ReBAC implementation based on a userset-rewrite graph:
      - primitives: union (list), This, ComputedUserset, TupleToUserset
      - safety limits: max_depth, max_nodes, deadline_ms
      - conditional tuples via a caveat registry (predicate by name)
    """

    def __init__(
        self,
        store: InMemoryRelationshipStore,
        *,
        # rules: mapping[object_type][relation] -> UsersetExpr
        rules: dict[str, dict[str, UsersetExpr]] | None = None,
        caveat_registry: dict[str, Callable[[dict[str, Any] | None], bool]] | None = None,
        max_depth: int = 8,
        max_nodes: int = 10000,
        deadline_ms: int = 50,
    ) -> None:
        self.store = store
        self.rules = rules or {}
        self.caveats = caveat_registry or {}
        self.max_depth = max_depth
        self.max_nodes = max_nodes
        self.deadline_ms = deadline_ms

    # --------------- public API ---------------

    def check(
        self, subject: str, relation: str, resource: str, *, context: dict[str, Any] | None = None
    ) -> bool:
        start = time.perf_counter_ns()
        deadline = start + self.deadline_ms * 1_000_000
        visits = 0

        # breadth-first search over the userset rewrite graph
        queue: list[tuple[str, str, str, int]] = [(subject, relation, resource, 0)]
        seen: set[tuple[str, str, str]] = set()

        while queue:
            s, rel, obj, depth = queue.pop(0)

            if (s, rel, obj) in seen:
                continue
            seen.add((s, rel, obj))

            visits += 1
            if visits > self.max_nodes:
                return False
            if depth > self.max_depth:
                continue
            if time.perf_counter_ns() > deadline:
                return False

            # 1) direct tuples ("this")
            if self._direct_allowed(s, rel, obj, context):
                return True

            # 2) userset-rewrite for the object's type
            obj_type, _ = _split_ref(obj)
            expr = self._lookup_expr(obj_type, rel)
            if expr is None:
                # no rewrite rule for the relation -> only direct tuples could match
                continue

            # expand next frontier nodes from the expression
            for s2, r2, o2 in self._expand(expr, s, obj):
                queue.append((s2, r2, o2, depth + 1))

        return False

    def batch_check(
        self, triples: list[tuple[str, str, str]], *, context: dict[str, Any] | None = None
    ) -> list[bool]:
        # Simple sequential evaluation with a tiny per-call memo
        memo: dict[tuple[str, str, str], bool] = {}
        out: list[bool] = []
        for s, r, o in triples:
            key = (s, r, o)
            if key in memo:
                out.append(memo[key])
            else:
                res = self.check(s, r, o, context=context)
                memo[key] = res
                out.append(res)
        return out

    # --------------- internals ---------------

    def _direct_allowed(
        self, subject: str, relation: str, resource: str, context: dict[str, Any] | None
    ) -> bool:
        for t in self.store.direct_for_resource(relation, resource):
            if t.subject != subject:
                continue
            if t.caveat is None:
                return True
            # conditional relation handled via a registered predicate
            pred = self.caveats.get(t.caveat)
            if pred is None:
                # unknown caveat -> treat as False
                continue
            try:
                if bool(pred(context)):
                    return True
            except Exception as exc:
                # failed predicate -> treat as False
                logger.warning(
                    "ReBAC caveat '%s' failed for (%s, %s, %s): %s",
                    t.caveat,
                    subject,
                    relation,
                    resource,
                    exc,
                    exc_info=True,
                )
                continue
        return False

    def _lookup_expr(self, obj_type: str, relation: str) -> UsersetExpr | None:
        return (self.rules.get(obj_type) or {}).get(relation)

    def _expand(
        self, expr: UsersetExpr, subject: str, resource: str
    ) -> Iterable[tuple[str, str, str]]:
        """
        Convert a userset expression into next BFS nodes:
        yields (subject, relation, resource)
        """
        if isinstance(expr, list):
            # union
            for e in expr:
                yield from self._expand(e, subject, resource)
            return
        if isinstance(expr, This):
            # already handled direct tuples earlier; no new edges to traverse
            return
        if isinstance(expr, ComputedUserset):
            # evaluate another relation on the SAME object
            yield subject, expr.relation, resource
            return
        if isinstance(expr, TupleToUserset):
            # follow an object->object edge from the current resource to a target object,
            # then evaluate 'computed_userset' on that target object
            for edge in self.store.direct_for_resource(expr.tupleset, resource):
                if ":" not in edge.subject:
                    continue
                target_obj = edge.subject
                yield subject, expr.computed_userset, target_obj
            return
        # unknown/extension nodes are ignored
        return
