"""rbacx AI Policy Authoring System.

Optional module — install with::

    pip install rbacx[ai]

Provides AI-assisted policy generation, iterative refinement, and
human-readable decision explanations using any OpenAI-compatible LLM.

Quick start::

    from rbacx.ai import AIPolicy

    ai = AIPolicy(api_key="sk-...", model="gpt-4o")

    # Generate a policy from an OpenAPI schema
    result = await ai.from_schema("openapi.json", context="SaaS B2B")

    # Use the policy with Guard
    from rbacx.core.engine import Guard
    guard = Guard(result.dsl)

    # Refine iteratively
    result2 = await ai.refine_policy("deny delete for viewer role")

    # Explain a specific decision
    expl = await ai.explain_decision(
        policy=result.dsl,
        input={
            "subject": {"id": "u1", "roles": ["viewer"]},
            "action": "delete",
            "resource": {"type": "doc", "id": "d1"},
        },
    )
    print(expl.decision.allowed)  # False
    print(expl.human)             # plain-English explanation
"""

from rbacx.ai._result import DecisionExplanation, PolicyResult
from rbacx.ai.exceptions import (
    PolicyGenerationError,
    SchemaParseError,
    ValidationRetryError,
)
from rbacx.ai.policy import AIPolicy

__all__ = [
    "AIPolicy",
    "PolicyResult",
    "DecisionExplanation",
    "SchemaParseError",
    "ValidationRetryError",
    "PolicyGenerationError",
]
