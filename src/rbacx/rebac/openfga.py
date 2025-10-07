from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from typing import Any, Mapping

try:
    import httpx  # optional dependency (declare extra: rebac-openfga)
except Exception:  # pragma: no cover
    httpx = None  # type: ignore[assignment]

from ..core.ports import RelationshipChecker

logger = logging.getLogger("rbacx.rebac.openfga")


@dataclass(frozen=True)
class OpenFGAConfig:
    """Minimal configuration for OpenFGA HTTP client."""

    api_url: str  # e.g. "http://localhost:8080"
    store_id: str  # e.g. "01H..." (required for most endpoints)
    authorization_model_id: str | None = None
    api_token: str | None = None  # Bearer <token>, if your deployment requires it
    timeout_seconds: float = 2.0


class OpenFGAChecker(RelationshipChecker):
    """ReBAC provider backed by OpenFGA HTTP API.

    - Uses /stores/{store_id}/check and /stores/{store_id}/batch-check.
    - If `authorization_model_id` is set in config (or passed per-call), it is forwarded.
    - `context` (if any) is forwarded to support OpenFGA "conditions".
      OpenFGA merges persisted context with request context; persisted wins on conflict.
      See docs.  # https://openfga.dev/docs/modeling/conditions
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
                "OpenFGAChecker requires 'httpx' installed. "
                "Install with extra: rbacx[rebac-openfga]."
            )
        self.cfg = config
        self._client = client
        self._aclient = async_client

        if self._client is None and self._aclient is None:
            # Default to sync client; you can pass AsyncClient to return awaitables.
            self._client = httpx.Client(timeout=self.cfg.timeout_seconds)

    # ------------- helpers -------------

    def _headers(self) -> dict[str, str]:
        h = {"content-type": "application/json"}
        if self.cfg.api_token:
            h["authorization"] = f"Bearer {self.cfg.api_token}"
        return h

    def _url(self, suffix: str) -> str:
        base = self.cfg.api_url.rstrip("/")
        return f"{base}/stores/{self.cfg.store_id}/{suffix.lstrip('/')}"

    # ------------- RelationshipChecker -------------

    def check(  # overload-compatible: sync OR async depends on which client is provided
        self,
        subject: str,
        relation: str,
        resource: str,
        *,
        context: dict[str, Any] | None = None,
        authorization_model_id: str | None = None,
    ):
        body: dict[str, Any] = {
            # REST form with tuple_key is canonical for raw API
            "tuple_key": {"user": subject, "relation": relation, "object": resource},
        }
        model_id = authorization_model_id or self.cfg.authorization_model_id
        if model_id:
            body["authorization_model_id"] = model_id
        if context:
            body["context"] = context

        if self._aclient is not None:

            async def _run() -> bool:
                resp = await self._aclient.post(
                    self._url("check"), json=body, headers=self._headers()
                )
                resp.raise_for_status()
                data = resp.json()
                return bool(data.get("allowed", False))

            return _run()

        # sync
        assert self._client is not None
        resp = self._client.post(self._url("check"), json=body, headers=self._headers())
        resp.raise_for_status()
        data = resp.json()
        return bool(data.get("allowed", False))

    def batch_check(
        self,
        triples: list[tuple[str, str, str]],
        *,
        context: dict[str, Any] | None = None,
        authorization_model_id: str | None = None,
    ):
        # Build server-side BatchCheck payload
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
                resp = await self._aclient.post(
                    self._url("batch-check"), json=body, headers=self._headers()
                )
                resp.raise_for_status()
                data = resp.json() or {}
                # Response shape maps correlation_id -> {allowed: bool}
                # See docs for Batch Check.  # https://openfga.dev/docs/getting-started/perform-check
                results_map: Mapping[str, Mapping[str, Any]] = data.get("results") or {}
                out: list[bool] = []
                for cid in corr_ids:
                    allowed = bool((results_map.get(cid) or {}).get("allowed", False))
                    out.append(allowed)
                return out

            return _run()

        # sync
        assert self._client is not None
        resp = self._client.post(self._url("batch-check"), json=body, headers=self._headers())
        resp.raise_for_status()
        data = resp.json() or {}
        results_map: Mapping[str, Mapping[str, Any]] = data.get("results") or {}
        out: list[bool] = []
        for cid in corr_ids:
            allowed = bool((results_map.get(cid) or {}).get("allowed", False))
            out.append(allowed)
        return out
