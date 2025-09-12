from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import Any, Dict, Literal, Optional, Tuple

from ..core.ports import PolicySource

logger = logging.getLogger("rbacx.storage.s3")


_S3_URL_RE = re.compile(r"^s3://(?P<bucket>[^/]+)/(?P<key>.+)$")


@dataclass(frozen=True)
class _S3Location:
    bucket: str
    key: str


def _parse_s3_url(url: str) -> _S3Location:
    """
    Parse s3://bucket/key into (_S3Location). Raises ValueError on invalid input.
    """
    m = _S3_URL_RE.match(url)
    if not m:
        raise ValueError(f"Invalid S3 URL: {url!r} (expected s3://bucket/key)")
    return _S3Location(bucket=m.group("bucket"), key=m.group("key"))


class S3PolicySource(PolicySource):
    """
    Policy source backed by Amazon S3.

    Change detection strategies (choose one via `change_detector`):
      - "etag"        : Use HeadObject ETag (default). Note: for multipart uploads the ETag
                        is not a simple MD5, but it remains a stable identifier for change.
      - "version_id"  : Use the VersionId returned by HeadObject (requires bucket versioning).
      - "checksum"    : Use GetObjectAttributes(..., ObjectAttributes=['Checksum']) and prefer
                        server-provided checksum (sha256/crc32c/sha1/md5) if available, else fallback.

    Networking defaults are production-friendly (timeouts + retries) and can be overridden
    by passing a custom botocore Config via `botocore_config` or additional kwargs through
    `client_params`.

    This class does not persist local state; a higher-level reloader should compare ETags/versions.
    """

    def __init__(
        self,
        url: str,
        *,
        validate_schema: bool = False,
        change_detector: Literal["etag", "version_id", "checksum"] = "etag",
        prefer_checksum: Optional[Literal["sha256", "crc32c", "sha1", "md5"]] = "sha256",
        # boto3/botocore injection/customization:
        session: Any | None = None,  # boto3.session.Session | None
        botocore_config: Any | None = None,  # botocore.config.Config | None
        client_params: Optional[
            Dict[str, Any]
        ] = None,  # extra params for boto3.client("s3", **...)
    ) -> None:
        self.loc = _parse_s3_url(url)
        self.validate_schema = validate_schema
        self.change_detector = change_detector
        self.prefer_checksum = prefer_checksum
        self._client = self._build_client(session, botocore_config, client_params or {})

    # --------------------------------------------------------------------- #
    # Client setup
    # --------------------------------------------------------------------- #

    @staticmethod
    def _build_client(session: Any | None, cfg: Any | None, extra: Dict[str, Any]) -> Any:
        """
        Create a boto3 S3 client with sensible defaults:
          - connect/read timeouts
          - standard retry mode with a few attempts
        """
        try:
            import boto3  # type: ignore
            from botocore.config import Config  # type: ignore
        except Exception as e:  # pragma: no cover
            raise ImportError(
                "S3PolicySource requires boto3 and botocore. "
                "Install with: pip install boto3 botocore"
            ) from e

        if cfg is None:
            cfg = Config(
                retries={"max_attempts": 4, "mode": "standard"},
                connect_timeout=3,
                read_timeout=8,
            )

        if session is None:
            session = boto3.session.Session()  # type: ignore[attr-defined]

        return session.client("s3", config=cfg, **extra)

    # --------------------------------------------------------------------- #
    # PolicySource interface
    # --------------------------------------------------------------------- #

    def etag(self) -> Optional[str]:
        """
        Return a stable identifier of the current object state according to `change_detector`.
        The exact string format is namespaced to avoid collisions across strategies.
        """
        try:
            if self.change_detector == "etag":
                etag = self._head_etag()
                return f"etag:{etag}" if etag is not None else None
            elif self.change_detector == "version_id":
                vid = self._head_version_id()
                # If versioning is disabled, fallback to ETag so caller still gets change detection.
                if vid is None:
                    etag = self._head_etag()
                    return f"etag:{etag}" if etag is not None else None
                return f"vid:{vid}"
            else:  # "checksum"
                cks = self._get_checksum()
                if cks is None:
                    # Fallback to ETag if server-side checksums are unavailable.
                    etag = self._head_etag()
                    return f"etag:{etag}" if etag is not None else None
                algo, value = cks
                return f"ck:{algo}:{value}"
        except self._client.exceptions.NoSuchKey:  # pragma: no cover
            return None
        except Exception:
            # Prefer to let the reloader handle suppression/backoff on errors.
            raise

    def load(self) -> Dict[str, Any]:
        """
        Fetch the object via GetObject and parse JSON; optionally validate schema.
        """
        body = self._get_object_bytes()
        policy = json.loads(body.decode("utf-8"))

        if self.validate_schema:
            try:
                from rbacx.dsl.validate import validate_policy  # type: ignore[import-not-found]

                validate_policy(policy)
            except Exception as e:  # pragma: no cover
                logger.exception("RBACX: policy validation failed", exc_info=e)
                raise

        return policy

    # --------------------------------------------------------------------- #
    # S3 calls
    # --------------------------------------------------------------------- #

    def _head(self) -> Dict[str, Any]:
        """
        Call HeadObject to obtain metadata quickly (no body).
        """
        return self._client.head_object(Bucket=self.loc.bucket, Key=self.loc.key)

    def _head_etag(self) -> Optional[str]:
        """
        Retrieve object's ETag from HeadObject. Strip quotes if present.
        """
        try:
            resp = self._head()
        except self._client.exceptions.NoSuchKey:
            return None
        etag = resp.get("ETag")
        if not etag:
            return None
        return etag.strip('"')

    def _head_version_id(self) -> Optional[str]:
        """
        Retrieve VersionId from HeadObject (only when bucket versioning is enabled).
        """
        try:
            resp = self._head()
        except self._client.exceptions.NoSuchKey:
            return None
        # HeadObject includes VersionId in response when applicable.
        vid = resp.get("VersionId")
        return vid if isinstance(vid, str) else None

    def _get_checksum(self) -> Optional[Tuple[str, str]]:
        """
        Retrieve server-side checksum via GetObjectAttributes(ObjectAttributes=['Checksum']).
        Returns (algo, value) or None if not available.
        """
        try:
            resp = self._client.get_object_attributes(
                Bucket=self.loc.bucket,
                Key=self.loc.key,
                ObjectAttributes=["Checksum"],
            )
        except self._client.exceptions.NoSuchKey:
            return None
        except Exception:
            # Some endpoints or older S3-compatible servers may not support GetObjectAttributes.
            return None

        # Prefer the requested algorithm if present; otherwise pick the first available.
        candidates: Dict[str, Optional[str]] = {
            "sha256": resp.get("ChecksumSHA256"),
            "crc32c": resp.get("ChecksumCRC32C"),
            "sha1": resp.get("ChecksumSHA1"),
            "md5": resp.get(
                "ChecksumCRC32"
            ),  # MD5 is not exposed here; CRC32 is, keep as last resort.
        }

        if self.prefer_checksum and candidates.get(self.prefer_checksum):
            return self.prefer_checksum, candidates[self.prefer_checksum]  # type: ignore[return-value]

        for algo in ("sha256", "crc32c", "sha1", "md5"):
            val = candidates.get(algo)
            if val:
                return algo, val
        return None

    def _get_object_bytes(self) -> bytes:
        """
        Download object content via GetObject and return as bytes.
        """
        resp = self._client.get_object(Bucket=self.loc.bucket, Key=self.loc.key)
        # Streaming body must be fully read and closed.
        body = resp["Body"].read()
        resp["Body"].close()
        return body
