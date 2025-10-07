from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

# Optional dependencies: grpc + authzed (official client)
# pip install authzed grpcio grpcio-tools
try:
    from authzed.api.v1 import (
        CheckPermissionRequest,
        Consistency,
        ObjectReference,
        SubjectReference,
    )
    from authzed.api.v1 import (
        Client as ZedClient,
    )
    from authzed.api.v1 import (
        InsecureClient as ZedInsecureClient,
    )
except Exception:  # pragma: no cover
    ZedClient = None  # type: ignore[assignment]

from ..core.ports import RelationshipChecker

logger = logging.getLogger("rbacx.rebac.spicedb")


@dataclass(frozen=True)
class SpiceDBConfig:
    """Minimal configuration for SpiceDB/Authzed gRPC client."""

    endpoint: str  # "grpc.authzed.com:443" or "localhost:50051"
    token: str | None = None
    insecure: bool = False  # True for local/dev without TLS
    prefer_fully_consistent: bool = False  # else: at-least-as-fresh (default)
    timeout_seconds: float = 2.0


class SpiceDBChecker(RelationshipChecker):
    """ReBAC provider backed by SpiceDB/Authzed gRPC.

    - Uses CheckPermission (and BulkCheckPermission if available).
    - Supports Consistency via ZedToken or fully_consistent flag.
    - For caveated (conditional) tuples, forwards request `context` to CEL.
      See "Caveats" and "Consistency" in the docs.
    """

    def __init__(self, config: SpiceDBConfig) -> None:
        if ZedClient is None:
            raise RuntimeError(
                "SpiceDBChecker requires 'authzed' and 'grpcio'. "
                "Install with extra: rbacx[rebac-spicedb]"
            )
        self.cfg = config

        if config.insecure:
            self._client = ZedInsecureClient(config.endpoint, config.token or "")
            self._aclient = None
        else:
            # Prefer sync client by default; expose AsyncClient via explicit factory if needed.
            self._client = ZedClient(config.endpoint, self._bearer(config.token))
            self._aclient = None  # could be ZedAsyncClient(...)

    # ------------- RelationshipChecker -------------

    def check(
        self,
        subject: str,
        relation: str,
        resource: str,
        *,
        context: dict[str, Any] | None = None,
        zed_token: str | None = None,
    ):
        """Return bool (sync). If you initialize with AsyncClient, return awaitable."""
        req = CheckPermissionRequest(
            resource=ObjectReference(
                object_type=resource.split(":", 1)[0],
                object_id=resource.split(":", 1)[1] if ":" in resource else resource,
            ),
            permission=relation,
            subject=SubjectReference(
                object=ObjectReference(
                    object_type=subject.split(":", 1)[0],
                    object_id=subject.split(":", 1)[1] if ":" in subject else subject,
                )
            ),
        )

        # Consistency selection
        if zed_token:
            req.consistency = Consistency(at_least_as_fresh={"token": zed_token})
        elif self.cfg.prefer_fully_consistent:
            req.consistency = Consistency(fully_consistent=True)

        # Caveat context
        if context:
            # 'context' is forwarded as named parameters for CEL caveats
            req.context = context  # authzed client handles Any map

        if self._aclient is not None:

            async def _run() -> bool:
                resp = await self._aclient.CheckPermission(req, timeout=self.cfg.timeout_seconds)
                return getattr(resp, "permissionship", 0) == 1  # HAS_PERMISSION

            return _run()

        resp = self._client.CheckPermission(req, timeout=self.cfg.timeout_seconds)
        return getattr(resp, "permissionship", 0) == 1  # HAS_PERMISSION

    def batch_check(
        self,
        triples: list[tuple[str, str, str]],
        *,
        context: dict[str, Any] | None = None,
        zed_token: str | None = None,
    ):
        """Use BulkCheckPermission if available; otherwise, fall back to sequential checks."""
        # Fallback: sequential (keeps implementation simple; switch to BulkCheck later if needed)
        if self._aclient is not None:

            async def _run() -> list[bool]:
                out: list[bool] = []
                for s, r, o in triples:
                    out.append(await self.check(s, r, o, context=context, zed_token=zed_token))
                return out

            return _run()

        return [self.check(s, r, o, context=context, zed_token=zed_token) for (s, r, o) in triples]

    # ------------- helpers -------------

    @staticmethod
    def _bearer(token: str | None):
        """Return gRPC call credentials for Bearer token."""
        if not token:  # pragma: no cover
            raise ValueError("SpiceDB token is required for secure client")
        from authzed.api.v1 import bearer_token_credentials

        return bearer_token_credentials(token)
