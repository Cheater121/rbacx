"""Shared pytest fixtures for the rbacx.ai test suite.

All fixtures that reference rbacx.ai internals are guarded so the entire
tests/ai directory can be *collected* even when the optional ``openai``
dependency is not installed.  Individual tests that need the real import
chain will either skip via ``pytest.importorskip("openai")`` or rely on
the mock already in place.
"""

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

# ---------------------------------------------------------------------------
# LLM client mock
# ---------------------------------------------------------------------------

VALID_POLICY_JSON = """{
    "algorithm": "deny-overrides",
    "rules": [
        {
            "id": "task_read",
            "effect": "permit",
            "actions": ["read"],
            "resource": {"type": "task"}
        }
    ]
}"""


@pytest.fixture()
def valid_policy_dict() -> dict[str, Any]:
    """Minimal valid rbacx policy dict (permit read on task)."""
    return {
        "algorithm": "deny-overrides",
        "rules": [
            {
                "id": "task_read",
                "effect": "permit",
                "actions": ["read"],
                "resource": {"type": "task"},
            }
        ],
    }


@pytest.fixture()
def multi_rule_policy_dict() -> dict[str, Any]:
    """Policy with multiple rules for explanation tests."""
    return {
        "algorithm": "deny-overrides",
        "rules": [
            {
                "id": "task_read",
                "effect": "permit",
                "actions": ["read"],
                "resource": {"type": "task"},
            },
            {
                "id": "task_admin_delete",
                "effect": "permit",
                "actions": ["delete"],
                "resource": {"type": "task"},
                "condition": {
                    "hasAny": [
                        {"attr": "subject.roles"},
                        ["admin"],
                    ]
                },
            },
        ],
    }


@pytest.fixture()
def mock_llm_client(valid_policy_json: str = VALID_POLICY_JSON) -> MagicMock:
    """Mock LLMClient whose complete() returns a valid policy JSON string."""
    client = MagicMock()
    client.complete = AsyncMock(return_value=valid_policy_json)
    return client


@pytest.fixture()
def make_mock_llm_client():
    """Factory fixture: returns a mock LLMClient with configurable response."""

    def _make(response: str = VALID_POLICY_JSON) -> MagicMock:
        client = MagicMock()
        client.complete = AsyncMock(return_value=response)
        return client

    return _make


# ---------------------------------------------------------------------------
# Normalised schema fixtures — imported lazily so collection works without openai
# ---------------------------------------------------------------------------


@pytest.fixture()
def sample_normalized_schema():
    """NormalizedSchema with two resources (task, project)."""
    from rbacx.ai._schema_parser import NormalizedEndpoint, NormalizedSchema  # noqa: PLC0415

    return NormalizedSchema(
        title="TaskManagerAPI",
        version="1.0.0",
        endpoints=[
            NormalizedEndpoint(
                path="/tasks",
                method="GET",
                resource_type="task",
                action="read",
                summary="List tasks",
                description=None,
                requires_auth=True,
                error_codes=[401, 403],
            ),
            NormalizedEndpoint(
                path="/tasks",
                method="POST",
                resource_type="task",
                action="create",
                summary="Create task",
                description=None,
                requires_auth=True,
                error_codes=[401, 403],
            ),
            NormalizedEndpoint(
                path="/tasks/{id}",
                method="DELETE",
                resource_type="task",
                action="delete",
                summary="Delete task",
                description=None,
                requires_auth=True,
                error_codes=[401, 403, 404],
            ),
            NormalizedEndpoint(
                path="/projects",
                method="GET",
                resource_type="project",
                action="read",
                summary="List projects",
                description=None,
                requires_auth=True,
                error_codes=[401],
            ),
        ],
    )


# ---------------------------------------------------------------------------
# Raw OpenAPI dicts — no third-party imports, always available
# ---------------------------------------------------------------------------


@pytest.fixture()
def sample_openapi3_dict() -> dict[str, Any]:
    """Minimal valid OpenAPI 3.0 dict."""
    return {
        "openapi": "3.0.0",
        "info": {"title": "TaskManagerAPI", "version": "1.0.0"},
        "paths": {
            "/tasks": {
                "get": {
                    "tags": ["task"],
                    "summary": "List tasks",
                    "parameters": [
                        {
                            "name": "x-jwt-token",
                            "in": "header",
                            "required": True,
                            "schema": {"type": "string"},
                        }
                    ],
                    "responses": {
                        "200": {"description": "OK"},
                        "401": {"description": "Unauthorized"},
                        "403": {"description": "Forbidden"},
                    },
                },
                "post": {
                    "tags": ["task"],
                    "summary": "Create task",
                    "parameters": [
                        {
                            "name": "x-jwt-token",
                            "in": "header",
                            "required": True,
                            "schema": {"type": "string"},
                        }
                    ],
                    "responses": {
                        "201": {"description": "Created"},
                        "401": {"description": "Unauthorized"},
                    },
                },
            },
            "/tasks/{id}": {
                "delete": {
                    "tags": ["task"],
                    "summary": "Delete task",
                    "parameters": [
                        {
                            "name": "x-jwt-token",
                            "in": "header",
                            "required": True,
                            "schema": {"type": "string"},
                        }
                    ],
                    "responses": {
                        "204": {"description": "Deleted"},
                        "401": {"description": "Unauthorized"},
                        "403": {"description": "Forbidden"},
                        "404": {"description": "Not Found"},
                    },
                }
            },
            "/projects": {
                "get": {
                    "tags": ["project"],
                    "summary": "List projects",
                    "parameters": [
                        {
                            "name": "x-jwt-token",
                            "in": "header",
                            "required": True,
                            "schema": {"type": "string"},
                        }
                    ],
                    "responses": {
                        "200": {"description": "OK"},
                        "401": {"description": "Unauthorized"},
                    },
                }
            },
        },
    }


@pytest.fixture()
def sample_openapi2_dict() -> dict[str, Any]:
    """Minimal valid OpenAPI 2.0 (Swagger) dict."""
    return {
        "swagger": "2.0",
        "info": {"title": "TaskManagerAPI", "version": "1.0.0"},
        "paths": {
            "/tasks": {
                "get": {
                    "tags": ["task"],
                    "summary": "List tasks",
                    "parameters": [
                        {
                            "name": "x-jwt-token",
                            "in": "header",
                            "required": True,
                            "type": "string",
                        }
                    ],
                    "responses": {
                        "200": {"description": "OK"},
                        "401": {"description": "Unauthorized"},
                    },
                }
            }
        },
    }
