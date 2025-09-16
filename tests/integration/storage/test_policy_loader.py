import json

from rbacx.core.engine import Guard
from rbacx.core.model import Action, Context, Resource, Subject
from rbacx.policy.loader import HotReloader, load_policy

# Helper policies
DENY_ALL = {
    "algorithm": "deny-overrides",
    "rules": [{"id": "deny_all", "effect": "deny", "actions": ["*"], "resource": {"type": "doc"}}],
}
PERMIT_READ = {
    "algorithm": "deny-overrides",
    "rules": [
        {"id": "permit_read", "effect": "permit", "actions": ["read"], "resource": {"type": "doc"}}
    ],
}


def _eval_read(guard: Guard) -> str:
    d = guard.evaluate_sync(
        Subject(id="u"),
        Action("read"),
        Resource(type="doc"),
        Context(),
    )
    return d.effect


class MemorySource:
    """Simple in-memory PolicySource for deterministic tests."""

    def __init__(self, policy: dict, etag: str | None):
        self._policy = policy
        self._etag = etag

    def set(self, *, policy: dict | None = None, etag: str | None = None):
        if policy is not None:
            self._policy = policy
        if etag is not None:
            self._etag = etag

    # PolicySource API
    def load(self) -> dict:
        # return a deep copy to simulate a fresh load from source
        return json.loads(json.dumps(self._policy))

    def etag(self) -> str | None:
        return self._etag


def test_hot_reloader_initial_load_false_noop_then_reload():
    """Default behavior (initial_load=False): first check is a NO-OP while etag is unchanged."""
    guard = Guard(DENY_ALL)
    src = MemorySource(policy=PERMIT_READ, etag="v1")

    rld = HotReloader(guard, src, initial_load=False, poll_interval=0.01)

    # First check should be a NO-OP because constructor primed _last_etag to 'v1'
    changed = rld.check_and_reload()
    assert changed is False
    assert _eval_read(guard) == "deny"

    # Change etag -> policy should load
    src.set(etag="v2")
    changed = rld.check_and_reload()
    assert changed is True
    assert _eval_read(guard) == "permit"


def test_hot_reloader_initial_load_true_loads_on_first_check():
    """With initial_load=True the first check loads the current policy immediately."""
    guard = Guard(DENY_ALL)
    src = MemorySource(policy=PERMIT_READ, etag="seed")

    rld = HotReloader(guard, src, initial_load=True, poll_interval=0.01)
    changed = rld.check_and_reload()
    assert changed is True
    assert _eval_read(guard) == "permit"


def test_hot_reloader_force_ignores_etag():
    """force=True must bypass the ETag check and apply the policy."""
    guard = Guard(DENY_ALL)
    src = MemorySource(policy=PERMIT_READ, etag="v1")

    # initial_load=False primes etag to v1 -> normal check would NO-OP
    rld = HotReloader(guard, src, initial_load=False)

    changed = rld.check_and_reload(force=True)
    assert changed is True
    assert _eval_read(guard) == "permit"


def test_hot_reloader_start_with_initial_load_and_force():
    """start(initial_load=True, force_initial=True) performs a synchronous load before the thread starts."""
    guard = Guard(DENY_ALL)
    src = MemorySource(policy=PERMIT_READ, etag="k1")

    rld = HotReloader(
        guard, src, initial_load=False, poll_interval=10.0
    )  # large interval to avoid background reloads
    rld.start(initial_load=True, force_initial=True)
    # Synchronous initial load already happened; don't wait.
    assert _eval_read(guard) == "permit"

    # Clean up thread
    rld.stop()


def test_load_policy_convenience(tmp_path):
    p = tmp_path / "policy.json"
    p.write_text(json.dumps(PERMIT_READ), encoding="utf-8")
    pol = load_policy(str(p))
    assert isinstance(pol, dict) and pol.get("rules")
