from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any, Dict, Literal, Optional, Tuple

from ..core.ports import PolicySource
from .policy_loader import parse_policy_bytes

logger = logging.getLogger("rbacx.store.s3")

_S3_URL_RE = re.compile(r"^s3://(?P<bucket>[^/]+)/(?P<key>.+)$")


@dataclass(frozen=True)
class _S3Location:
    bucket: str
    key: str


def _parse_s3_url(url: str) -> _S3Location:
    """Parse s3://bucket/key URLs into components."""
    m = _S3_URL_RE.match(url)
    if not m:
        raise ValueError(f"Invalid S3 URL: {url!r} (expected s3://bucket/key)")
    return _S3Location(bucket=m.group("bucket"), key=m.group("key"))


class S3PolicySource(PolicySource):
    """
    Policy source backed by Amazon S3.

    Change detection strategies (choose one via `change_detector`):
      - "etag"        : HeadObject ETag (default).
      - "version_id"  : HeadObject VersionId (requires bucket versioning).
      - "checksum"    : GetObjectAttributes(..., ObjectAttributes=['Checksum']) if available.

    Networking defaults are production-friendly (timeouts + retries) and can be overridden
    via a custom botocore Config or client parameters.
    """

    def __init__(
        self,
        url: str,
        *,
        client: Any | None = None,
        session: Any | None = None,
        config: Any | None = None,
        client_extra: Dict[str, Any] | None = None,
        validate_schema: bool = True,
        change_detector: Literal["etag", "version_id", "checksum"] = "etag",
        # preferred checksum when `change_detector="checksum"`
        prefer_checksum: Optional[
            Literal["sha256", "crc32c", "sha1", "crc32", "crc64nvme"]
        ] = "sha256",
    ) -> None:
        self.loc = _parse_s3_url(url)
        self._client = client or self._build_client(session, config, client_extra or {})
        self.validate_schema = validate_schema
        self.change_detector = change_detector
        self.prefer_checksum = prefer_checksum
        self._etag: Optional[str] = None  # cached last seen ETag (if obtained via load())

    # ---------- AWS client helpers ----------

    @staticmethod
    def _build_client(session: Any | None, cfg: Any | None, extra: Dict[str, Any]) -> Any:
        """Construct a boto3 S3 client with sensible defaults.

        This function is isolated to make unit-testing easier (tests monkeypatch it).
        """
        import boto3  # type: ignore[import-untyped, import-not-found]

        try:
            from botocore.config import Config  # type: ignore[import-untyped, import-not-found]
        except Exception:  # pragma: no cover - very old botocore
            Config = None

        # Build a default Config if none provided
        if cfg is None and Config is not None:
            # Reasonable timeouts & retries
            cfg = Config(
                retries={"max_attempts": 5, "mode": "standard"},
                connect_timeout=3,
                read_timeout=10,
            )

        # Prefer boto3.session.Session to be compatible with test stubs
        if session is not None:
            sess = session
        else:
            try:
                sess = boto3.session.Session()
            except Exception:  # pragma: no cover - fallback if aliasing differs
                sess = boto3.Session()

        if cfg is not None:
            return sess.client("s3", config=cfg, **(extra or {}))
        return sess.client("s3", **(extra or {}))

    # ---------- Change detectors ----------

    def etag(self) -> Optional[str]:
        """Return the current change marker according to `change_detector`."""
        if self.change_detector == "etag":
            et = self._head_etag()
            return f"etag:{et}" if et else None

        if self.change_detector == "version_id":
            vid = self._head_version_id()
            if vid:
                return f"vid:{vid}"
            # fallback to ETag if versioning is disabled or VersionId is absent
            et = self._head_etag()
            return f"etag:{et}" if et else None

        if self.change_detector == "checksum":
            ck = self._get_checksum()
            if ck:
                algo, value = ck
                return f"ck:{algo}:{value}"
            # fallback to ETag if checksum is unavailable
            et = self._head_etag()
            return f"etag:{et}" if et else None

        # defensive default
        et = self._head_etag()
        return f"etag:{et}" if et else None

    def _head(self) -> Dict[str, Any]:
        """HEAD the object safely, returning a (possibly empty) dict."""
        try:
            return self._client.head_object(Bucket=self.loc.bucket, Key=self.loc.key)
        except getattr(self._client, "exceptions", object()).__dict__.get("NoSuchKey", Exception):
            return {}
        except Exception:  # pragma: no cover - network/credentials issues
            logger.debug("RBACX: S3 head_object failed", exc_info=True)
            return {}

    def _head_etag(self) -> Optional[str]:
        data = self._head()
        etag = data.get("ETag")
        if isinstance(etag, str) and len(etag) >= 2 and etag.startswith('"') and etag.endswith('"'):
            return etag[1:-1]
        return etag if isinstance(etag, str) else None

    def _head_version_id(self) -> Optional[str]:
        data = self._head()
        ver = data.get("VersionId")
        return ver if isinstance(ver, str) else None

    def _get_checksum(self) -> Optional[Tuple[str, str]]:
        """Fetch an object checksum using GetObjectAttributes.

        Returns a pair (algorithm, value) or None if unavailable.

        Supported algorithms (as returned by S3): sha256, crc32c, sha1, crc32, crc64nvme
        """
        try:
            resp = self._client.get_object_attributes(
                Bucket=self.loc.bucket,
                Key=self.loc.key,
                ObjectAttributes=["Checksum"],
            )
        except getattr(self._client, "exceptions", object()).__dict__.get("NoSuchKey", Exception):
            return None
        except Exception:
            # API not available or permissions denied
            return None

        candidates: Dict[str, Optional[str]] = {
            "sha256": resp.get("ChecksumSHA256"),
            "crc32c": resp.get("ChecksumCRC32C"),
            "sha1": resp.get("ChecksumSHA1"),
            # NOTE: this is CRC32 (NOT MD5). MD5 is not exposed via GetObjectAttributes; it's in ETag.
            "crc32": resp.get("ChecksumCRC32"),
            # Newer AWS checksum for some storage classes/devices
            "crc64nvme": resp.get("ChecksumCRC64NVME"),
        }

        # If the preferred algorithm is present, use it
        if self.prefer_checksum:
            val = candidates.get(self.prefer_checksum)
            if val:
                return self.prefer_checksum, val

        # Otherwise, pick the first available in a deterministic order
        for algo in ("sha256", "crc32c", "sha1", "crc32", "crc64nvme"):
            val = candidates.get(algo)
            if val:
                return algo, val
        return None

    # ---------- Data loading ----------

    def _get_object_bytes(self) -> bytes:
        resp = self._client.get_object(Bucket=self.loc.bucket, Key=self.loc.key)
        # Update cached ETag if provided
        etag = resp.get("ETag")
        if isinstance(etag, str) and len(etag) >= 2 and etag.startswith('"') and etag.endswith('"'):
            self._etag = etag[1:-1]
        elif isinstance(etag, str):
            self._etag = etag
        body = resp["Body"].read()
        resp["Body"].close()
        return body

    def load(self) -> Dict[str, Any]:
        """Download and parse the policy document from S3.

        The format (JSON vs YAML) is auto-detected using the object key (filename) and/or content.
        """
        raw = self._get_object_bytes()

        policy = parse_policy_bytes(raw, filename=self.loc.key)

        if self.validate_schema:
            try:
                from rbacx.dsl.validate import validate_policy

                validate_policy(policy)
            except Exception as e:  # pragma: no cover
                logger.exception("RBACX: policy validation failed", exc_info=e)
                raise

        return policy


__all__ = ["S3PolicySource", "_parse_s3_url"]
