
from __future__ import annotations

import json
from typing import Any, Dict, Optional


class S3PolicySource:
    """S3 policy source using boto3.
    Extra: rbacx[s3]
    """
    def __init__(self, bucket: str, key: str, *, aws_region: str | None = None) -> None:
        self.bucket = bucket
        self.key = key
        self.aws_region = aws_region
        self._etag: Optional[str] = None

    def load(self) -> Dict[str, Any]:
        try:
            import boto3  # type: ignore
        except Exception as e:  # pragma: no cover
            raise RuntimeError("boto3 is required for S3PolicySource (pip install rbacx[s3])") from e
        s3 = boto3.client("s3", region_name=self.aws_region) if self.aws_region else boto3.client("s3")
        resp = s3.get_object(Bucket=self.bucket, Key=self.key)
        self._etag = (resp.get("ETag") or "").strip('"')
        body = resp["Body"].read()
        return json.loads(body.decode("utf-8"))

    def etag(self) -> Optional[str]:
        return self._etag
