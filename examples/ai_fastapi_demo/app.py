"""AI-assisted policy generation demo for FastAPI.

This demo shows how to wire FastAPI's auto-generated OpenAPI schema directly
into the rbacx AI Policy Authoring System, so the LLM produces a policy that
matches the actual routes and their intended access rules — no manual JSON
authoring required.

Install requirements:
    pip install rbacx[ai] fastapi uvicorn

Configure:
    export RBACX_AI_API_KEY="sk-..."            # OpenAI key (or any compatible)
    export RBACX_AI_MODEL="gpt-4o"              # optional, default gpt-4o
    export RBACX_AI_BASE_URL=""                 # optional, e.g. OpenRouter URL

Run:
    uvicorn examples.ai_fastapi_demo.app:app --reload --port 8010

How it works:
    1. FastAPI builds its OpenAPI schema from the route definitions below.
    2. On startup, the schema is passed to AIPolicy.from_schema() with a short
       context string describing the app's intent.
    3. The LLM returns a valid rbacx policy dict (linted, ready to use).
    4. A Guard is created from the generated policy and wired into the routes
       via the require_access() dependency.
    5. If generation fails, the app falls back to a safe default policy.

Test:
    curl http://127.0.0.1:8010/ping
    curl http://127.0.0.1:8010/docs        # FastAPI Swagger UI
    curl -H "X-User: alice" http://127.0.0.1:8010/documents
    curl -H "X-User: alice" -H "X-Role: viewer" http://127.0.0.1:8010/documents
    curl -H "X-Role: admin" http://127.0.0.1:8010/documents/1
    curl -H "X-Role: admin" http://127.0.0.1:8010/reports/monthly
"""

import logging
import os
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, Request
from fastapi.openapi.utils import get_openapi

from rbacx import Action, Context, Guard, Resource, Subject
from rbacx.adapters.fastapi import require_access

logger = logging.getLogger("ai_fastapi_demo")
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

# ---------------------------------------------------------------------------
# Fallback policy — used when AI generation is skipped or fails
# ---------------------------------------------------------------------------

_FALLBACK_POLICY: dict[str, Any] = {
    "algorithm": "deny-overrides",
    "rules": [
        {
            "id": "permit-viewer-read-documents",
            "effect": "permit",
            "actions": ["read"],
            "resource": {"type": "document"},
            "roles": ["viewer", "editor", "admin"],
        },
        {
            "id": "permit-editor-write-documents",
            "effect": "permit",
            "actions": ["write"],
            "resource": {"type": "document"},
            "roles": ["editor", "admin"],
        },
        {
            "id": "permit-admin-reports",
            "effect": "permit",
            "actions": ["read"],
            "resource": {"type": "report"},
            "roles": ["admin"],
        },
    ],
}

# ---------------------------------------------------------------------------
# Guard — populated on startup
# ---------------------------------------------------------------------------

# Start with fallback; replaced on startup if AI generation succeeds.
_guard = Guard(_FALLBACK_POLICY)
_generated_policy: dict[str, Any] | None = None


async def _generate_policy(openapi_schema: dict[str, Any]) -> dict[str, Any] | None:
    """Ask the LLM to generate a policy from the app's OpenAPI schema.

    Returns the policy dict on success, None on any error (caller uses fallback).
    """
    api_key = os.environ.get("RBACX_AI_API_KEY", "")
    if not api_key:
        logger.info("RBACX_AI_API_KEY not set — skipping AI generation, using fallback policy.")
        return None

    try:
        from rbacx.ai import AIPolicy  # noqa: PLC0415  (lazy import, optional dep)
    except ImportError:
        logger.warning("rbacx[ai] not installed — using fallback policy.")
        return None

    model = os.environ.get("RBACX_AI_MODEL", "gpt-5.4-mini")
    base_url = os.environ.get("RBACX_AI_BASE_URL") or None

    ai = AIPolicy(api_key=api_key, model=model, base_url=base_url)

    context = (
        "Document management SaaS API.  "
        "Three roles: viewer (read only), editor (read + write documents), "
        "admin (full access including reports).  "
        "Resources: document, report.  "
        "Deny by default."
    )

    logger.info("Generating rbacx policy via AI (model=%s)…", model)
    try:
        result = await ai.from_schema(openapi_schema, context=context)
    except Exception as exc:
        # LLM returned invalid JSON, network error, rate limit, etc.
        # Log and fall back to the built-in policy — never crash on startup.
        logger.warning(
            "AI policy generation failed (%s: %s) — using fallback policy.",
            type(exc).__name__,
            exc,
        )
        return None

    if result.warnings:
        logger.warning("AI policy lint warnings: %s", result.warnings)
    else:
        logger.info("AI policy generated successfully — no lint warnings.")

    return result.dsl


# ---------------------------------------------------------------------------
# App + lifespan
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI):
    """On startup: extract OpenAPI schema → generate policy → wire Guard."""
    global _guard, _generated_policy

    # FastAPI builds OpenAPI lazily; force it now so we can pass it to the AI.
    schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description or "",
        routes=app.routes,
    )

    policy = await _generate_policy(schema)

    if policy is not None:
        _generated_policy = policy
        _guard = Guard(policy)
        logger.info("Guard updated with AI-generated policy.")
    else:
        logger.info("Guard using fallback policy.")

    yield  # app runs here


app = FastAPI(
    title="Document Management API",
    version="1.0.0",
    description=(
        "Demo API for the rbacx AI Policy Authoring System.  "
        "On startup the OpenAPI schema is sent to an LLM which generates "
        "a matching rbacx policy automatically."
    ),
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------
# EnvBuilder factory — one function: action and resource type as params
# ---------------------------------------------------------------------------


def make_env(action: str, resource_type: str):
    """Return an EnvBuilder that extracts subject from request headers.

    Args:
        action: the action string passed to ``Action`` (e.g. ``"read"``).
        resource_type: the resource type string (e.g. ``"document"``).

    The returned callable reads two headers from the request:
        - ``X-User``  — subject id (default: ``"anonymous"``).
        - ``X-Role``  — single role assigned to the subject (default: ``"viewer"``).

    In production replace header parsing with real authentication logic.
    """

    def _build(request: Request):
        user = request.headers.get("X-User", "anonymous")
        role = request.headers.get("X-Role", "viewer")
        return (
            Subject(id=user, roles=[role]),
            Action(action),
            Resource(type=resource_type),
            Context(),
        )

    _build.__name__ = f"build_env_{action}_{resource_type}"
    return _build


# ---------------------------------------------------------------------------
# Guard accessor — always reads the current _guard (updated on startup)
# ---------------------------------------------------------------------------


def get_guard() -> Guard:
    return _guard


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.get("/ping", tags=["Health"])
async def ping():
    """Health check — no authentication required."""
    return {"pong": True}


@app.get("/policy", tags=["Debug"])
async def current_policy():
    """Return the active rbacx policy (generated or fallback).

    Useful for debugging — remove in production.
    """
    return {
        "source": "ai-generated" if _generated_policy is not None else "fallback",
        "policy": _guard.policy,
    }


@app.get(
    "/documents",
    tags=["Documents"],
    summary="List documents",
    description="Returns a list of documents. Requires viewer role or higher.",
    dependencies=[
        Depends(require_access(get_guard(), make_env("read", "document"), add_headers=True))
    ],
)
async def list_documents():
    return {"documents": ["doc-1", "doc-2", "doc-3"]}


@app.get(
    "/documents/{doc_id}",
    tags=["Documents"],
    summary="Get a document",
    description="Returns a single document by ID. Requires viewer role or higher.",
    dependencies=[
        Depends(require_access(get_guard(), make_env("read", "document"), add_headers=True))
    ],
)
async def get_document(doc_id: str):
    return {"doc_id": doc_id, "content": "…"}


@app.post(
    "/documents",
    tags=["Documents"],
    summary="Create a document",
    description="Creates a new document. Requires editor role or higher.",
    dependencies=[
        Depends(require_access(get_guard(), make_env("write", "document"), add_headers=True))
    ],
)
async def create_document(request: Request):
    return {"created": True}


@app.get(
    "/reports/monthly",
    tags=["Reports"],
    summary="Monthly report",
    description="Returns the monthly summary report. Admin only.",
    dependencies=[
        Depends(require_access(get_guard(), make_env("read", "report"), add_headers=True))
    ],
)
async def monthly_report():
    return {"report": "monthly", "data": []}
