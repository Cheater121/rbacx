import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import given
from hypothesis import strategies as st

from rbacx.core.engine import Guard


def _normalize(g: Guard, env: dict) -> str:
    return g._normalize_env_for_cache(env)


def _env_strategy():
    # Recursive strategy for nested dict/list primitives
    leaf = st.one_of(st.none(), st.booleans(), st.integers(), st.floats(allow_nan=False), st.text())
    container = st.deferred(
        lambda: st.one_of(
            st.lists(leaf, max_size=3),
            st.dictionaries(st.text(min_size=1, max_size=5), leaf, max_size=3),
        )
    )
    attrs = st.dictionaries(st.text(min_size=1, max_size=5), st.one_of(leaf, container), max_size=3)

    def make_env(attrs_map):
        return {
            "subject": {"id": "u", "roles": [], "attrs": attrs_map},
            "action": "read",
            "resource": {"type": "doc", "id": "1", "attrs": {}},
            "context": {},
        }

    return attrs.map(make_env)


@given(_env_strategy())
def test_normalization_deterministic_and_stable(env):
    g = Guard({"rules": []})
    s1 = _normalize(g, env)
    # mutate order by creating a new dict with reversed items (if possible)
    env2 = {
        "subject": {
            "id": env["subject"]["id"],
            "roles": list(env["subject"]["roles"]),
            "attrs": dict(reversed(list(env["subject"]["attrs"].items())))
            if env["subject"]["attrs"]
            else {},
        },
        "action": env["action"],
        "resource": dict(env["resource"]),
        "context": dict(env["context"]),
    }
    s2 = _normalize(g, env2)
    assert s1 == s2
