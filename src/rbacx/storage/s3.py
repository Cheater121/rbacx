from __future__ import annotations

# Backwards-compatibility shim: re-export from rbacx.store.s3
from ..store.s3_store import S3PolicySource

__all__ = ["S3PolicySource"]
