import importlib
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

# Optional: install via extra rbacx[rebac-spicedb]
try:
    from authzed.api.v1 import (
        CheckPermissionRequest,
        CheckPermissionResponse,
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
    from grpc import RpcError  # type: ignore
except Exception:  # pragma: no cover
    ZedClient = None  # type: ignore

if TYPE_CHECKING:
    # for type-checkers only; no runtime import -> avoids "__all__" complaints
    pass  # type: ignore

from ..core.ports import RelationshipChecker

logger = logging.getLogger("rbacx.rebac.spicedb")


@dataclass(frozen=True)
class SpiceDBConfig:
    """Minimal configuration for SpiceDB/Authzed gRPC client."""

    endpoint: str  # e.g. "grpc.authzed.com:443" or "localhost:50051"
    token: str | None = None
    insecure: bool = False  # True for local/dev without TLS
    prefer_fully_consistent: bool = False
    timeout_seconds: float = 2.0


class SpiceDBChecker(RelationshipChecker):
    """
    ReBAC provider backed by SpiceDB/Authzed gRPC.

    - Uses CheckPermission; for batch, falls back to sequential checks.
    - Supports Consistency via ZedToken (at_least_as_fresh) or fully_consistent.
    - For caveated (conditional) tuples, forwards `context` map for CEL evaluation.
    """

    def __init__(self, config: SpiceDBConfig, *, async_mode: bool = False) -> None:
        if ZedClient is None:
            raise RuntimeError(
                "SpiceDBChecker requires 'authzed' and 'grpcio'. "
                "Install with extra: rbacx[rebac-spicedb]"
            )
        self.cfg = config
        self._async = async_mode

        if config.insecure:
            # Dev/local (no TLS, token passed as plain string)
            self._client = ZedInsecureClient(config.endpoint, config.token or "")
            self._aclient = None
        else:
            if async_mode:
                # Avoid importing AsyncClient at module import time (may not be exported in __all__)
                try:
                    azv1 = importlib.import_module("authzed.api.v1")
                    AsyncClient = azv1.AsyncClient
                except Exception as exc:  # pragma: no cover
                    raise RuntimeError(
                        "authzed.api.v1.AsyncClient is not available; "
                        "update 'authzed' package or disable async_mode."
                    ) from exc
                self._client = None
                self._aclient = AsyncClient(config.endpoint, self._bearer(config.token))
            else:
                # TLS + bearer credentials (via grpcutil)
                self._client = ZedClient(config.endpoint, self._bearer(config.token))
                self._aclient = None

    # -------------- RelationshipChecker --------------

    def check(
        self,
        subject: str,
        relation: str,
        resource: str,
        *,
        context: dict[str, Any] | None = None,
        zed_token: str | None = None,
    ):
        obj_type, obj_id = (resource.split(":", 1) + [""])[:2]
        subj_type, subj_id = (subject.split(":", 1) + [""])[:2]

        req = CheckPermissionRequest(
            resource=ObjectReference(object_type=obj_type, object_id=obj_id),
            permission=relation,
            subject=SubjectReference(
                object=ObjectReference(object_type=subj_type, object_id=subj_id)
            ),
        )

        # Consistency
        if zed_token:
            req.consistency = Consistency(at_least_as_fresh={"token": zed_token})
        elif self.cfg.prefer_fully_consistent:
            req.consistency = Consistency(fully_consistent=True)

        # Caveats context
        if context:
            req.context = context  # SDK converts dict to google.protobuf.Struct

        if getattr(self, "_aclient", None) is not None:

            async def _run() -> bool:
                try:
                    resp = await self._aclient.CheckPermission(
                        req, timeout=self.cfg.timeout_seconds
                    )
                    return (
                        resp.permissionship == CheckPermissionResponse.PERMISSIONSHIP_HAS_PERMISSION
                    )
                except RpcError as e:  # type: ignore[name-defined]
                    logger.warning("SpiceDB async check RPC error: %s", e, exc_info=True)
                    return False
                except Exception:  # pragma: no cover
                    logger.error("SpiceDB async check unexpected error", exc_info=True)
                    return False

            return _run()

        if getattr(self, "_client", None) is None:
            raise RuntimeError("No sync gRPC client configured for SpiceDBChecker")

        try:
            resp = self._client.CheckPermission(req, timeout=self.cfg.timeout_seconds)
            return resp.permissionship == CheckPermissionResponse.PERMISSIONSHIP_HAS_PERMISSION
        except RpcError as e:  # type: ignore[name-defined]
            logger.warning("SpiceDB check RPC error: %s", e, exc_info=True)
            return False
        except Exception:  # pragma: no cover
            logger.error("SpiceDB check unexpected error", exc_info=True)
            return False

    def batch_check(
        self,
        triples: list[tuple[str, str, str]],
        *,
        context: dict[str, Any] | None = None,
        zed_token: str | None = None,
    ):
        if getattr(self, "_aclient", None) is not None:

            async def _run() -> list[bool]:
                out: list[bool] = []
                for s, r, o in triples:
                    out.append(await self.check(s, r, o, context=context, zed_token=zed_token))
                return out

            return _run()

        # sync fallback
        return [self.check(s, r, o, context=context, zed_token=zed_token) for (s, r, o) in triples]

    # -------------- helpers --------------

    @staticmethod
    def _bearer(token: str | None):
        """Return gRPC call credentials for TLS-enabled Client.

        NOTE: For insecure/dev usage we never call this; we use InsecureClient
        which accepts the raw token string directly.
        """
        if not token:  # pragma: no cover
            raise ValueError("SpiceDB token is required for secure client")
        try:
            # Official pattern: creds live in top-level 'grpcutil' module.
            # from grpcutil import bearer_token_credentials  (dynamic to avoid stub issues)
            grpcutil = importlib.import_module("grpcutil")
            bearer_token_credentials = grpcutil.bearer_token_credentials
        except Exception as exc:  # pragma: no cover
            raise RuntimeError(
                "Authzed 'grpcutil.bearer_token_credentials' is not available. "
                "Upgrade/install the 'authzed' client library."
            ) from exc
        return bearer_token_credentials(token)
