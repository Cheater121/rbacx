"""Stateful multi-turn policy refinement session."""

import time
from dataclasses import dataclass, field
from typing import Any

from rbacx.ai._client import LLMClient
from rbacx.ai._generator import PolicyGenerator
from rbacx.ai._prompt import PromptBuilder
from rbacx.ai._result import PolicyResult
from rbacx.ai._validator import PolicyValidator
from rbacx.ai.exceptions import PolicyGenerationError


@dataclass
class RefinementIteration:
    """Snapshot of a single refinement step.

    Attributes:
        feedback: the natural-language instruction that triggered this
                  iteration.
        policy: the policy dict produced after applying the feedback.
        warnings: lint issues for the produced policy.
        timestamp: :func:`time.time` value at the moment the iteration
                   was recorded.
    """

    feedback: str
    policy: dict[str, Any]
    warnings: list[Any]
    timestamp: float = field(default_factory=time.time)


class RefinementSession:
    """Stateful multi-turn policy refinement with full conversation history.

    Keeps the LLM conversation history across :meth:`refine` calls so the
    model retains context of every previous feedback and decision.

    The session is intentionally **not** frozen — it is a long-lived object
    that accumulates state.  Callers obtain a session from
    :meth:`~rbacx.ai.policy.AIPolicy.from_schema` and drive it forward
    through successive :meth:`refine` calls.

    Args:
        client: configured :class:`~rbacx.ai._client.LLMClient` instance.
        generator: shared :class:`~rbacx.ai._generator.PolicyGenerator`
                   instance.
        validator: shared :class:`~rbacx.ai._validator.PolicyValidator`
                   instance.
        initial_policy: the policy dict that serves as the starting point
                        for the first :meth:`refine` call.
        initial_messages: the conversation messages produced during
                          :meth:`~rbacx.ai.policy.AIPolicy.from_schema`;
                          used as the base for the first refinement prompt.
    """

    def __init__(
        self,
        client: LLMClient,
        generator: PolicyGenerator,
        validator: PolicyValidator,
        initial_policy: dict[str, Any],
        initial_messages: list[dict[str, str]],
    ) -> None:
        self._client = client
        self._generator = generator
        self._validator = validator
        self._current_policy: dict[str, Any] = initial_policy
        self._messages: list[dict[str, str]] = list(initial_messages)
        self._history: list[RefinementIteration] = []

    # ------------------------------------------------------------------
    # Public properties
    # ------------------------------------------------------------------

    @property
    def current_policy(self) -> dict[str, Any]:
        """Most recent policy dict — initial or post-refinement."""
        return self._current_policy

    @property
    def history(self) -> list[RefinementIteration]:
        """Ordered list of all refinement iterations, oldest first."""
        return list(self._history)

    # ------------------------------------------------------------------
    # Core operation
    # ------------------------------------------------------------------

    async def refine(
        self,
        feedback: str,
        *,
        compile: bool = False,
    ) -> PolicyResult:
        """Refine the current policy with natural-language *feedback*.

        Always runs the ``safe_mode`` validation pipeline
        (generate → validate → retry on failure → lint).

        The conversation history is extended with the current policy as an
        assistant message and *feedback* as a user message before each LLM
        call, so the model accumulates context across calls.

        If validation ultimately fails the session state is **not** updated
        (the ``current_policy`` and ``history`` remain unchanged) and the
        exception propagates to the caller.

        Args:
            feedback: natural-language refinement instruction, e.g.
                      ``"deny delete for viewer role"``.
            compile: if ``True``, compile the refined policy via the rbacx
                     compiler.  Raises :exc:`PolicyGenerationError` if the
                     compiler is unavailable.

        Returns:
            :class:`~rbacx.ai._result.PolicyResult` with the refined
            ``dsl``, ``warnings``, and optionally ``compiled``.

        Raises:
            ValidationRetryError: both validation attempts fail.
            PolicyGenerationError: JSON parse error, or ``compile=True``
                                   and compiler unavailable.
        """
        messages = PromptBuilder.build_refine(self._messages, self._current_policy, feedback)

        # generate() runs safe_mode pipeline internally
        new_policy, raw = await self._generator.generate(messages, safe_mode=True)
        warnings = self._validator.lint(new_policy)
        compiled = self._compile(new_policy) if compile else None

        # Update session state only after full success
        self._messages = messages
        self._current_policy = new_policy
        self._history.append(
            RefinementIteration(
                feedback=feedback,
                policy=new_policy,
                warnings=warnings,
                timestamp=time.time(),
            )
        )

        return PolicyResult(
            dsl=new_policy,
            warnings=warnings,
            compiled=compiled,
            explanation=None,
            raw=None,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _compile(policy: dict[str, Any]) -> Any:
        """Compile *policy*. Raises :exc:`PolicyGenerationError` if unavailable."""
        try:
            from rbacx.core.compiler import compile as compile_policy  # noqa: PLC0415
        except Exception as exc:
            raise PolicyGenerationError(
                "compile=True requested but the rbacx compiler is unavailable. "
                "This is unexpected — ensure rbacx is installed correctly.",
                cause=exc,
            ) from exc
        return compile_policy(policy)
