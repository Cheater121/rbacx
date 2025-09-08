from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Optional

from ..core.engine import Guard
from ..core.ports import PolicySource


class FilePolicySource:
    """Загрузка JSON-политики из файла и расчёт etag (sha256 содержимого)."""

    def __init__(self, path: str) -> None:
        self.path = path
        self._etag: Optional[str] = None

    def etag(self) -> Optional[str]:
        try:
            with open(self.path, "rb") as f:
                data = f.read()
        except FileNotFoundError:
            return None
        sha = hashlib.sha256(data).hexdigest()
        self._etag = sha
        return sha

    def load(self) -> Dict[str, Any]:
        with open(self.path, "r", encoding="utf-8") as f:
            return json.load(f)


class ReloadingPolicyManager:
    """Следит за источником и при смене etag подменяет политику в Guard."""

    def __init__(self, source: PolicySource, guard: Guard) -> None:
        self.source = source
        self.guard = guard
        self._last: Optional[str] = getattr(guard, "policy_etag", None)

    def refresh_if_needed(self) -> bool:
        try:
            current = self.source.etag()
            if not current or current == self._last:
                return False
            policy = self.source.load()
            # у Guard есть set_policy (добавлено ранее), используем её
            self.guard.set_policy(policy)
            self._last = getattr(self.guard, "policy_etag", current)
            return True
        except Exception:
            # глушим любые ошибки и сигнализируем об отсутствии обновления
            return False
