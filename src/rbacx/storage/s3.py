from __future__ import annotations

import json
import logging
from typing import Any, Dict, Optional

from ..core.ports import PolicySource

logger = logging.getLogger("rbacx.storage.s3")


class S3PolicySource(PolicySource):
    """
    Load policy JSON from an S3 object.

    Boto3 is imported lazily at runtime to avoid a hard dependency at import time.
    """

    def __init__(
        self,
        bucket: str,
        key: str,
        *,
        profile_name: Optional[str] = None,
        region_name: Optional[str] = None,
        validate_schema: bool = False,
    ) -> None:
        self.bucket = bucket
        self.key = key
        self.profile_name = profile_name
        self.region_name = region_name
        self.validate_schema = validate_schema
        # lazily created boto3 S3 client
        self._client: Any | None = None

    # -- internal -------------------------------------------------------------

    def _ensure(self) -> None:
        """Ensure that self._client is initialized."""
        if self._client is not None:
            return
        try:
            # Import lazily so that library users without boto3 can still import the module.
            import boto3  # type: ignore[import-not-found, import-untyped]
        except Exception as e:  # pragma: no cover - import error path
            logger.exception("RBACX: boto3 import failed", exc_info=e)
            raise

        try:
            if self.profile_name:
                session = boto3.Session(profile_name=self.profile_name)  # type: ignore[attr-defined]
            else:
                session = boto3.Session()  # type: ignore[attr-defined]
            self._client = session.client("s3", region_name=self.region_name)
        except Exception as e:  # pragma: no cover
            logger.exception("RBACX: failed to create boto3 S3 client", exc_info=e)
            raise

    # -- PolicySource API -----------------------------------------------------

    def etag(self) -> Optional[str]:
        self._ensure()
        client = self._client
        if client is None:  # for mypy
            return None
        try:
            resp = client.head_object(Bucket=self.bucket, Key=self.key)
            etag = resp.get("ETag")
            if isinstance(etag, str):
                return etag.strip('"')
        except Exception as e:  # pragma: no cover
            logger.exception("RBACX: head_object failed", exc_info=e)
        return None

    def load(self) -> Dict[str, Any]:
        self._ensure()
        client = self._client
        if client is None:  # for mypy
            raise RuntimeError("S3 client is not initialized")
        resp = client.get_object(Bucket=self.bucket, Key=self.key)
        body = resp["Body"].read().decode("utf-8")
        policy: Dict[str, Any] = json.loads(body)

        if self.validate_schema:
            try:
                from rbacx.dsl.validate import validate_policy  # type: ignore
                validate_policy(policy)
            except Exception as e:  # pragma: no cover
                logger.exception("RBACX: policy validation failed", exc_info=e)
                raise
        return policy
