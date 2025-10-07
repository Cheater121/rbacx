import logging
import uuid
from dataclasses import dataclass
from typing import Any, Mapping

try:
    import httpx  # optional dependency, install via extra: rbacx[rebac-openfga]
except Exception:  # pragma: no cover
    httpx = None  # type: ignore

from ..core.ports import RelationshipChecker

logger = logging.getLogger("rbacx.rebac.openfga")


@dataclass(frozen=True)
class OpenFGAConfig:
    """Minimal configuration for OpenFGA HTTP client."""

    api_url: str  # e.g. "http://localhost:8080"
    store_id: str  # e.g. "01H..." (required)
    authorization_model_id: str | None = None
    api_token: str | None = None  # Bearer <token>, if required
    timeout_seconds: float = 2.0


class OpenFGAChecker(RelationshipChecker):
    """
    ReBAC provider backed by OpenFGA HTTP API.

    - Uses /stores/{store_id}/check and /stores/{store_id}/batch-check.
    - For conditions, forwards `context` (OpenFGA merges persisted and request contexts).
    - If both clients are provided, AsyncClient takes precedence (methods return awaitables).
    """

    def __init__(
        self,
        config: OpenFGAConfig,
        *,
        client: "httpx.Client | None" = None,
        async_client: "httpx.AsyncClient | None" = None,
    ) -> None:
        if httpx is None:
            raise RuntimeError(
                "OpenFGAChecker requires 'httpx'. Install with extra: rbacx[rebac-openfga]"
            )
        self.cfg = config
        self._client = client
        self._aclient = async_client

        # Provide a sensible default: sync client if neither was passed.
        if self._client is None and self._aclient is None:
            self._client = httpx.Client(timeout=self.cfg.timeout_seconds)

    # ------------ helpers ------------

    def _headers(self) -> dict[str, str]:
        h = {"content-type": "application/json"}
        if self.cfg.api_token:
            h["authorization"] = f"Bearer {self.cfg.api_token}"
        return h

    def _url(self, suffix: str) -> str:
        base = self.cfg.api_url.rstrip("/")
        return f"{base}/stores/{self.cfg.store_id}/{suffix.lstrip('/')}"

    # ------------ RelationshipChecker ------------

    def check(  # overload-compatible: returns bool OR awaitable depending on client
        self,
        subject: str,
        relation: str,
        resource: str,
        *,
        context: dict[str, Any] | None = None,
        authorization_model_id: str | None = None,
    ):
        body: dict[str, Any] = {
            "tuple_key": {"user": subject, "relation": relation, "object": resource},
        }
        model_id = authorization_model_id or self.cfg.authorization_model_id
        if model_id:
            body["authorization_model_id"] = model_id
        if context:
            body["context"] = context

        if self._aclient is not None:

            async def _run() -> bool:
                try:
                    resp = await self._aclient.post(
                        self._url("check"),
                        json=body,
                        headers=self._headers(),
                        timeout=self.cfg.timeout_seconds,
                    )
                    resp.raise_for_status()
                    data = resp.json()
                    return bool(data.get("allowed", False))
                except httpx.HTTPError as e:  # type: ignore[attr-defined]
                    logger.warning("OpenFGA async check HTTP error: %s", e, exc_info=True)
                    return False
                except Exception:  # pragma: no cover
                    logger.error("OpenFGA async check unexpected error", exc_info=True)
                    return False

            return _run()

        if self._client is None:
            raise RuntimeError("No sync HTTP client configured for OpenFGAChecker")

        try:
            resp = self._client.post(
                self._url("check"),
                json=body,
                headers=self._headers(),
                timeout=self.cfg.timeout_seconds,
            )
            resp.raise_for_status()
            data = resp.json()
            return bool(data.get("allowed", False))
        except httpx.HTTPError as e:  # type: ignore[attr-defined]
            logger.warning("OpenFGA check HTTP error: %s", e, exc_info=True)
            return False
        except Exception:  # pragma: no cover
            logger.error("OpenFGA check unexpected error", exc_info=True)
            return False

    def batch_check(
        self,
        triples: list[tuple[str, str, str]],
        *,
        context: dict[str, Any] | None = None,
        authorization_model_id: str | None = None,
    ):
        # Build request with correlation_id per check (order is not guaranteed in responses)
        checks: list[dict[str, Any]] = []
        corr_ids: list[str] = []
        for s, r, o in triples:
            cid = str(uuid.uuid4())
            corr_ids.append(cid)
            checks.append(
                {
                    "tuple_key": {"user": s, "relation": r, "object": o},
                    "correlation_id": cid,
                }
            )

        body: dict[str, Any] = {"checks": checks}
        model_id = authorization_model_id or self.cfg.authorization_model_id
        if model_id:
            body["authorization_model_id"] = model_id
        if context:
            body["context"] = context

        if self._aclient is not None:

            async def _run() -> list[bool]:
                try:
                    resp = await self._aclient.post(
                        self._url("batch-check"),
                        json=body,
                        headers=self._headers(),
                        timeout=self.cfg.timeout_seconds,
                    )
                    resp.raise_for_status()
                    data = resp.json() or {}

                    # Support both API shapes:
                    # 1) REST map: {"results": { "<cid>": {"allowed": bool}, ... } }
                    # 2) SDK array: {"result": [ {"correlationId": "...", "allowed": bool}, ... ] }
                    out: list[bool] = []
                    if isinstance(data.get("results"), dict):
                        results_map: Mapping[str, Mapping[str, Any]] = data["results"]
                        for cid in corr_ids:
                            out.append(bool((results_map.get(cid) or {}).get("allowed", False)))
                        return out

                    if isinstance(data.get("result"), list):
                        by_cid = {
                            item.get("correlationId"): bool(item.get("allowed"))
                            for item in data["result"]
                        }
                        for cid in corr_ids:
                            out.append(bool(by_cid.get(cid, False)))
                        return out

                    return [False] * len(corr_ids)
                except httpx.HTTPError as e:  # type: ignore[attr-defined]
                    logger.warning("OpenFGA async batch-check HTTP error: %s", e, exc_info=True)
                    return [False] * len(corr_ids)
                except Exception:  # pragma: no cover
                    logger.error("OpenFGA async batch-check unexpected error", exc_info=True)
                    return [False] * len(corr_ids)

            return _run()

        if self._client is None:
            raise RuntimeError("No sync HTTP client configured for OpenFGAChecker")

        try:
            resp = self._client.post(
                self._url("batch-check"),
                json=body,
                headers=self._headers(),
                timeout=self.cfg.timeout_seconds,
            )
            resp.raise_for_status()
            data = resp.json() or {}

            out: list[bool] = []
            if isinstance(data.get("results"), dict):
                results_map: Mapping[str, Mapping[str, Any]] = data["results"]
                for cid in corr_ids:
                    out.append(bool((results_map.get(cid) or {}).get("allowed", False)))
                return out

            if isinstance(data.get("result"), list):
                by_cid = {
                    item.get("correlationId"): bool(item.get("allowed")) for item in data["result"]
                }
                for cid in corr_ids:
                    out.append(bool(by_cid.get(cid, False)))
                return out

            return [False] * len(corr_ids)
        except httpx.HTTPError as e:  # type: ignore[attr-defined]
            logger.warning("OpenFGA batch-check HTTP error: %s", e, exc_info=True)
            return [False] * len(corr_ids)
        except Exception:  # pragma: no cover
            logger.error("OpenFGA batch-check unexpected error", exc_info=True)
            return [False] * len(corr_ids)
