
from __future__ import annotations

import hashlib
import json
import os
from typing import Any, Dict, Optional


class FilePolicySource:
    """Policy source that loads JSON from a local file path."""
    def __init__(self, path: str) -> None:
        self.path = path
        self._etag: Optional[str] = None

    def load(self) -> Dict[str, Any]:
        with open(self.path, "rb") as f:
            data = f.read()
        self._etag = hashlib.sha256(data + str(os.path.getmtime(self.path)).encode()).hexdigest()
        return json.loads(data.decode("utf-8"))

    def etag(self) -> Optional[str]:
        return self._etag
