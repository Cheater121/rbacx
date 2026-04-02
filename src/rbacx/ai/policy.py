"""AIPolicy: main entry point for the AI Policy Authoring System."""

from pathlib import Path
from typing import Any

from rbacx.ai._client import LLMClient
from rbacx.ai._explainer import ExplainGenerator, PolicyExplainer
from rbacx.ai._generator import PolicyGenerator
from rbacx.ai._prompt import PromptBuilder
from rbacx.ai._refinement import RefinementSession
from rbacx.ai._result import DecisionExplanation, PolicyResult
from rbacx.ai._schema_parser import SchemaParser
from rbacx.ai._validator import PolicyValidator
from rbacx.ai.exceptions import PolicyGenerationError


class AIPolicy:
    """AI Policy Authoring System — main entry point.

    Creates one :class:`~rbacx.ai._client.LLMClient` instance that is
    reused across all operations.  After :meth:`from_schema` is called a
    :class:`~rbacx.ai._refinement.RefinementSession` is created internally
    and can be driven forward via :meth:`refine_policy`.

    Supports any OpenAI-compatible provider through the ``base_url``
    parameter — standard OpenAI, OpenRouter, Ollama, Azure OpenAI, etc.

    Args:
        api_key: API key for the LLM provider.
        model: model identifier, e.g. ``"gpt-4o"``,
               ``"anthropic/claude-3-5-sonnet"`` (OpenRouter),
               ``"llama3"`` (Ollama).
        base_url: optional base URL override.  ``None`` uses the standard
                  OpenAI endpoint.  Examples:
                  ``"https://openrouter.ai/api/v1"``,
                  ``"http://localhost:11434/v1"`` (Ollama).
        timeout: HTTP request timeout in seconds passed to the SDK.

    Example::

        ai = AIPolicy(api_key="sk-...", model="gpt-4o")
        result = await ai.from_schema("openapi.json", context="SaaS B2B")
        result2 = await ai.refine_policy(feedback="deny delete for viewers")
        expl = await ai.explain_decision(
            policy=result.dsl,
            input={
                "subject": {"id": "u1", "roles": ["viewer"]},
                "action": "delete",
                "resource": {"type": "doc", "id": "d1"},
            },
        )
    """

    def __init__(
        self,
        api_key: str,
        model: str,
        *,
        base_url: str | None = None,
        timeout: float = 60.0,
    ) -> None:
        self._client = LLMClient(
            api_key=api_key,
            model=model,
            base_url=base_url,
            timeout=timeout,
        )
        self._generator = PolicyGenerator(self._client)
        self._validator = PolicyValidator()
        self._explainer = PolicyExplainer(self._client)
        self._explain_gen = ExplainGenerator(self._client)
        self._session: RefinementSession | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def from_schema(
        self,
        schema: Path | str | dict[str, Any],
        *,
        context: str = "",
        safe_mode: bool = True,
        compile: bool = False,
        explain: bool = False,
        raw: bool = False,
    ) -> PolicyResult:
        """Generate an rbacx policy from an API schema.

        Resets any existing :class:`~rbacx.ai._refinement.RefinementSession`
        and creates a new one seeded with the generated policy and the
        conversation messages used during generation.

        Args:
            schema: OpenAPI 3.x or 2.0 schema supplied as:

                * a :class:`pathlib.Path` to a ``.json`` or ``.yaml`` file,
                * a file-path string,
                * a raw JSON string, or
                * a pre-loaded ``dict``.

            context: free-form domain description to guide generation,
                     e.g. ``"SaaS B2B, tenant isolation, admins per-org"``.
            safe_mode: run the validate → retry on failure → lint pipeline.
            compile: compile the policy via the rbacx compiler and include
                     the result in :attr:`PolicyResult.compiled`.  Raises
                     :exc:`PolicyGenerationError` if the compiler is
                     unavailable.
            explain: request per-rule human explanations (one extra LLM
                     call).  Result is in :attr:`PolicyResult.explanation`.
            raw: include the raw LLM output string in
                 :attr:`PolicyResult.raw` for debugging.

        Returns:
            :class:`~rbacx.ai._result.PolicyResult`.

        Raises:
            SchemaParseError: unrecognised schema format or unreadable file.
            PolicyGenerationError: JSON parse failure or ``compile=True``
                                   with unavailable compiler.
            ValidationRetryError: ``safe_mode=True`` and both validation
                                   attempts fail.
        """
        normalized = SchemaParser.parse(schema)
        messages = PromptBuilder.build_generation(normalized, context)

        policy_dict, raw_output = await self._generator.generate(messages, safe_mode=safe_mode)
        warnings = self._validator.lint(policy_dict)
        compiled = self._compile(policy_dict) if compile else None
        explanation = await self._explain_gen.explain_rules(policy_dict) if explain else None

        # Seed refinement session with generation messages as conversation base
        self._session = RefinementSession(
            client=self._client,
            generator=self._generator,
            validator=self._validator,
            initial_policy=policy_dict,
            initial_messages=messages,
        )

        return PolicyResult(
            dsl=policy_dict,
            warnings=warnings,
            compiled=compiled,
            explanation=explanation,
            raw=raw_output if raw else None,
        )

    async def refine_policy(
        self,
        feedback: str,
        *,
        policy: dict[str, Any] | None = None,
        compile: bool = False,
    ) -> PolicyResult:
        """Refine a policy with natural-language feedback.

        If *policy* is provided the current session is reset to that policy
        as the new starting point before applying *feedback*.  If *policy*
        is ``None`` the existing session is continued.

        Always runs the ``safe_mode`` validation pipeline internally.

        Args:
            feedback: natural-language refinement instruction, e.g.
                      ``"deny delete for viewer role"``.
            policy: optional policy dict to reset the session to before
                    refining.  If ``None`` and no session exists,
                    :exc:`RuntimeError` is raised.
            compile: compile the refined policy.  Raises
                     :exc:`PolicyGenerationError` if compiler unavailable.

        Returns:
            :class:`~rbacx.ai._result.PolicyResult` with the refined policy.

        Raises:
            RuntimeError: called before :meth:`from_schema` with no
                          *policy* argument.
            ValidationRetryError: validation fails after retry.
            PolicyGenerationError: JSON parse error or compiler unavailable.
        """
        if policy is not None:
            self._session = self._make_session_from_policy(policy)

        if self._session is None:
            raise RuntimeError(
                "No active policy session. "
                "Call from_schema() first, or pass policy= to refine_policy()."
            )

        return await self._session.refine(feedback, compile=compile)

    async def explain_decision(
        self,
        policy: dict[str, Any],
        input: dict[str, Any],
    ) -> DecisionExplanation:
        """Explain a specific access decision using Guard + LLM.

        The decision is evaluated **deterministically** by a minimal
        :class:`~rbacx.core.engine.Guard` instance — the LLM is never asked
        to decide allow/deny.  The LLM only produces the human-readable
        explanation of *why*.

        Args:
            policy: valid rbacx policy dict.
            input: access-request dict::

                {
                    "subject": {
                        "id": str,
                        "roles": list[str],  # optional
                        "attrs": dict,       # optional
                    },
                    "action": str,
                    "resource": {
                        "type": str,
                        "id": str | None,    # optional
                        "attrs": dict,       # optional
                    },
                }

        Returns:
            :class:`~rbacx.ai._result.DecisionExplanation` with the
            authoritative :class:`~rbacx.core.decision.Decision` and a
            plain-English explanation.

        Raises:
            PolicyGenerationError: *input* is malformed or missing required
                                   fields.
        """
        return await self._explainer.explain_decision(policy, input)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _make_session_from_policy(self, policy: dict[str, Any]) -> RefinementSession:
        """Create a new :class:`RefinementSession` from an explicit policy.

        Uses :meth:`PromptBuilder.build_refine` with empty history to
        produce minimal seed messages so the LLM has context about the
        starting policy.
        """
        messages = PromptBuilder.build_refine([], policy, "")
        return RefinementSession(
            client=self._client,
            generator=self._generator,
            validator=self._validator,
            initial_policy=policy,
            initial_messages=messages,
        )

    @staticmethod
    def _compile(policy: dict[str, Any]) -> Any:
        """Compile *policy*.  Raises :exc:`PolicyGenerationError` if unavailable."""
        try:
            from rbacx.core.compiler import compile as compile_policy  # noqa: PLC0415
        except Exception as exc:
            raise PolicyGenerationError(
                "compile=True requested but the rbacx compiler is unavailable. "
                "This is unexpected — ensure rbacx is installed correctly.",
                cause=exc,
            ) from exc
        return compile_policy(policy)
