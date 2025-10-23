import importlib
import logging
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from google.protobuf.struct_pb2 import Struct  # type: ignore[import-untyped]

# Optional: install via extra rbacx[rebac-spicedb]
try:
    from authzed.api.v1 import (
        CheckPermissionRequest,
        CheckPermissionResponse,
        Consistency,
        ObjectReference,
        SubjectReference,
        ZedToken,
    )
    from authzed.api.v1 import (
        Client as ZedClient,  # sync TLS client
    )
    from authzed.api.v1 import (
        InsecureClient as ZedInsecureClient,  # sync insecure client
    )
    from grpc import RpcError  # type: ignore[import-not-found,import-untyped]
except Exception:  # pragma: no cover
    ZedClient = None  # type: ignore[misc,assignment]

from ..core.ports import RelationshipChecker

logger = logging.getLogger("rbacx.rebac.spicedb")


@dataclass(frozen=True)
class SpiceDBConfig:
    """Minimal configuration for the SpiceDB/Authzed gRPC client."""

    endpoint: str  # "grpc.authzed.com:443" | "localhost:50051"
    token: str | None = None
    insecure: bool = False  # True for local/dev without TLS
    prefer_fully_consistent: bool = False
    timeout_seconds: float = 2.0


# ---- minimal typed protocols for the clients (common surface we use) ----


@runtime_checkable
class _ZedSyncClient(Protocol):
    def CheckPermission(
        self, request: CheckPermissionRequest, timeout: float | None = ...
    ) -> CheckPermissionResponse: ...


@runtime_checkable
class _ZedAsyncClient(Protocol):
    async def CheckPermission(
        self, request: CheckPermissionRequest, timeout: float | None = ...
    ) -> CheckPermissionResponse: ...


def _dict_to_struct(d: dict[str, Any]) -> Struct:
    s = Struct()
    # update() accepts a JSON-compatible dict; 64-bit integers should be strings (see docs)
    s.update(d)
    return s


class SpiceDBChecker(RelationshipChecker):
    """
    ReBAC provider backed by the SpiceDB/Authzed gRPC API.

    - Uses CheckPermission; batch -> sequential calls (gRPC has no one-shot batch).
    - Consistency: ZedToken (at_least_as_fresh) or fully_consistent.
    - Caveats: pass context as google.protobuf.Struct.
    """

    def __init__(self, config: SpiceDBConfig, *, async_mode: bool = False) -> None:
        if ZedClient is None:
            raise RuntimeError(
                "SpiceDBChecker requires 'authzed' and 'grpcio'. "
                "Install with extra: rbacx[rebac-spicedb]"
            )
        self.cfg = config

        # Explicit types for mypy: either the sync or async client is set (the other is None)
        self._client: _ZedSyncClient | None
        self._aclient: _ZedAsyncClient | None

        if config.insecure:
            # Dev/local (no TLS): pass the raw token string directly to InsecureClient
            self._client = ZedInsecureClient(config.endpoint, config.token or "")
            self._aclient = None
        else:
            if async_mode:
                # Import AsyncClient dynamically (avoid crashing if the symbol is absent in this version)
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
                # TLS client + bearer credentials (via grpcutil)
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
    ) -> (
        bool | Any
    ):  # Here Any = Awaitable[bool], but without 'from __future__ import annotations' mypy complains
        req = self._build_request(
            subject=subject,
            relation=relation,
            resource=resource,
            context=context,
            zed_token=zed_token,
        )

        if self._aclient is not None:
            aclient = self._aclient  # early binding to narrow the type

            async def _run() -> bool:
                try:
                    resp = await aclient.CheckPermission(req, timeout=self.cfg.timeout_seconds)
                    return (
                        resp.permissionship == CheckPermissionResponse.PERMISSIONSHIP_HAS_PERMISSION
                    )
                except RpcError as e:  # type: ignore[misc]
                    logger.warning("SpiceDB async check RPC error: %s", e, exc_info=True)
                    return False
                except Exception:  # pragma: no cover
                    logger.error("SpiceDB async check unexpected error", exc_info=True)
                    return False

            return _run()

        if self._client is None:
            raise RuntimeError("No sync gRPC client configured for SpiceDBChecker")

        try:
            resp = self._client.CheckPermission(req, timeout=self.cfg.timeout_seconds)
            return resp.permissionship == CheckPermissionResponse.PERMISSIONSHIP_HAS_PERMISSION
        except RpcError as e:  # type: ignore[misc]
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
    ) -> list[bool] | Any:  # Any = Awaitable[list[bool]]
        if self._aclient is not None:

            async def _run() -> list[bool]:
                out: list[bool] = []
                for s, r, o in triples:
                    out.append(
                        await self._check_single_async(
                            s, r, o, context=context, zed_token=zed_token
                        )
                    )
                return out

            return _run()

        # sync fallback
        return [self.check(s, r, o, context=context, zed_token=zed_token) for (s, r, o) in triples]

    # -------------- helpers --------------

    @staticmethod
    def _bearer(token: str | None):
        """Return gRPC call credentials for the TLS-enabled Client.

        NOTE: For insecure/dev usage we never call this; we use InsecureClient
        which accepts the raw token string directly.
        """
        if not token:  # pragma: no cover
            raise ValueError("SpiceDB token is required for secure client")
        try:
            # credentials live in the 'grpcutil' module from the 'authzed' package
            grpcutil = importlib.import_module("grpcutil")
            bearer_token_credentials = grpcutil.bearer_token_credentials
        except Exception as exc:  # pragma: no cover
            raise RuntimeError(
                "Authzed 'grpcutil.bearer_token_credentials' is not available. "
                "Upgrade/install the 'authzed' client library."
            ) from exc
        return bearer_token_credentials(token)

    def _build_request(
        self,
        *,
        subject: str,
        relation: str,
        resource: str,
        context: dict[str, Any] | None,
        zed_token: str | None,
    ) -> CheckPermissionRequest:
        obj_type, obj_id = (resource.split(":", 1) + [""])[:2]
        subj_type, subj_id = (subject.split(":", 1) + [""])[:2]

        consistency: Consistency | None = None
        if zed_token:
            consistency = Consistency(at_least_as_fresh=ZedToken(token=zed_token))
        elif self.cfg.prefer_fully_consistent:
            consistency = Consistency(fully_consistent=True)

        return CheckPermissionRequest(
            resource=ObjectReference(object_type=obj_type, object_id=obj_id),
            permission=relation,
            subject=SubjectReference(
                object=ObjectReference(object_type=subj_type, object_id=subj_id)
            ),
            consistency=consistency,
            context=_dict_to_struct(context) if context else None,
        )

    async def _check_single_async(
        self,
        subject: str,
        relation: str,
        resource: str,
        *,
        context: dict[str, Any] | None = None,
        zed_token: str | None = None,
    ) -> bool:
        """Pure async single-check for internal use."""
        aclient = self._aclient
        if aclient is None:
            raise RuntimeError("No async gRPC client configured for SpiceDBChecker")
        req = self._build_request(
            subject=subject,
            relation=relation,
            resource=resource,
            context=context,
            zed_token=zed_token,
        )
        try:
            resp = await aclient.CheckPermission(req, timeout=self.cfg.timeout_seconds)
            return resp.permissionship == CheckPermissionResponse.PERMISSIONSHIP_HAS_PERMISSION
        except RpcError as e:  # type: ignore[misc]
            logger.warning("SpiceDB async check RPC error: %s", e, exc_info=True)
            return False
        except Exception:  # pragma: no cover
            logger.error("SpiceDB async check unexpected error", exc_info=True)
            return False
