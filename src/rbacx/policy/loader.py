from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Optional

from ..core.engine import Guard
from ..core.ports import PolicySource


class FilePolicySource:
    """Loads JSON policy from a file and computes its etag (SHA-256 of its content)."""

    def __init__(self, path: str) -> None:
        self.path = path
        self._etag: Optional[str] = None

    def etag(self) -> Optional[str]:
        """
        Compute and return the current etag (SHA256 of file content).
        Returns None if the file does not exist.
        """
        try:
            with open(self.path, "rb") as f:
                data = f.read()
        except FileNotFoundError:
            return None
        sha = hashlib.sha256(data).hexdigest()
        self._etag = sha
        return sha

    def load(self) -> Dict[str, Any]:
        """
        Load and return the JSON policy from the file.
        Raises if the JSON is invalid or file cannot be read.
        """
        with open(self.path, "r", encoding="utf-8") as f:
            return json.load(f)


class ReloadingPolicyManager:
    """Monitors a policy source and updates the Guard when the etag changes."""

    def __init__(self, source: PolicySource, guard: Guard) -> None:
        self.source = source
        self.guard = guard
        # _last holds the previously known etag; start from guard.policy_etag if present
        self._last: Optional[str] = getattr(guard, "policy_etag", None)

    def refresh_if_needed(self) -> bool:
        """
        Check the source for changes and reload the policy into the guard if needed.

        Returns:
            True if the policy was reloaded (etag changed),
            False otherwise (same etag, missing file, or on error).
        """
        try:
            current = self.source.etag()
            if not current or current == self._last:
                return False
            policy = self.source.load()
            # Guard has set_policy (added earlier); use it
            self.guard.set_policy(policy)
            # Update the last known etag. Use guard.policy_etag if available, else the current etag.
            self._last = getattr(self.guard, "policy_etag", current)
            return True
        except Exception:
            # Suppress any errors and signal that no update occurred
            return False
