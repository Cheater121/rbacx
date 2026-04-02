"""PromptBuilder: pure static factory for LLM message lists."""

from importlib import resources
from typing import Any

from rbacx.ai._schema_parser import NormalizedSchema
from rbacx.core.decision import Decision

# ---------------------------------------------------------------------------
# System prompt — loaded once at module import from the bundled markdown file
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT: str = (
    resources.files("rbacx.ai._prompts").joinpath("system.md").read_text(encoding="utf-8")
)

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_ROLE_SYSTEM = "system"
_ROLE_USER = "user"
_ROLE_ASSISTANT = "assistant"


def _msg(role: str, content: str) -> dict[str, str]:
    return {"role": role, "content": content}


def _system() -> dict[str, str]:
    return _msg(_ROLE_SYSTEM, _SYSTEM_PROMPT)


# ---------------------------------------------------------------------------
# Public builder
# ---------------------------------------------------------------------------


class PromptBuilder:
    """Pure static factory for LLM message lists.

    Every method returns a *complete* ``messages`` list ready to pass
    directly to :meth:`rbacx.ai._client.LLMClient.complete`.

    No state is held — all methods are static.  The system prompt is loaded
    from ``_prompts/system.md`` once at module import and reused.
    """

    @staticmethod
    def build_generation(
        schema: NormalizedSchema,
        context: str = "",
    ) -> list[dict[str, str]]:
        """Build the initial policy-generation messages.

        Returns ``[system_message, user_message]``.  The user message
        contains the compact schema representation and, when non-empty,
        the free-form domain *context* provided by the caller.

        Args:
            schema: normalised schema to generate a policy for.
            context: optional free-form domain description
                     (e.g. ``"SaaS B2B, tenant isolation required"``).
        """
        parts: list[str] = [
            "Generate an rbacx policy for the following API schema.\n",
            "### API Schema\n",
            schema.to_prompt_repr(),
        ]
        if context.strip():
            parts.append(f"\n### Additional context\n{context.strip()}")
        parts.append(
            "\n### Instructions\n"
            "Return ONLY the policy as valid JSON. "
            "No markdown fences. No explanation. No preamble."
        )
        return [_system(), _msg(_ROLE_USER, "\n".join(parts))]

    @staticmethod
    def build_fix(
        previous_messages: list[dict[str, str]],
        raw_policy: str,
        validation_errors: list[str],
    ) -> list[dict[str, str]]:
        """Extend the conversation with a validation-fix request.

        Appends the bad policy as an *assistant* message and a *user*
        message that lists the validation errors and asks for a corrected
        policy.

        Args:
            previous_messages: the messages list from the previous attempt.
            raw_policy: the raw LLM output that failed validation.
            validation_errors: human-readable error strings from the validator.
        """
        errors_str = "\n".join(f"  - {e}" for e in validation_errors)
        fix_prompt = (
            "The policy you generated has validation errors. "
            "Fix ALL of them and return ONLY the corrected JSON "
            "(no markdown fences, no explanation).\n\n"
            f"Validation errors:\n{errors_str}"
        )
        return [
            *previous_messages,
            _msg(_ROLE_ASSISTANT, raw_policy),
            _msg(_ROLE_USER, fix_prompt),
        ]

    @staticmethod
    def build_refine(
        history: list[dict[str, str]],
        current_policy: dict[str, Any],
        feedback: str,
    ) -> list[dict[str, str]]:
        """Extend the conversation history with a refinement request.

        Appends the current policy as an *assistant* message and the
        caller's feedback as a *user* message.

        Args:
            history: existing conversation messages (may be empty for a
                     session started from an explicit policy dict).
            current_policy: the policy dict to refine.
            feedback: natural-language refinement instruction.
        """
        import json as _json

        policy_str = _json.dumps(current_policy, indent=2)
        user_content = (
            f"{feedback.strip()}\n\n"
            "Return ONLY the updated policy as valid JSON. "
            "No markdown fences. No explanation."
        )
        return [
            *history,
            _msg(_ROLE_ASSISTANT, policy_str),
            _msg(_ROLE_USER, user_content),
        ]

    @staticmethod
    def build_explain_rules(policy: dict[str, Any]) -> list[dict[str, str]]:
        """Build messages that ask the LLM to explain each rule.

        The LLM is instructed to return a JSON object mapping every
        ``rule_id`` to a plain-English explanation string.

        Args:
            policy: valid rbacx policy dict.
        """
        import json as _json

        policy_str = _json.dumps(policy, indent=2)
        user_content = (
            "For each rule in the following rbacx policy, write a single "
            "plain-English sentence explaining what the rule does and why.\n\n"
            f"Policy:\n{policy_str}\n\n"
            "Return ONLY a JSON object where keys are rule IDs and values are "
            'explanation strings. Example: {"rule_id": "explanation"}.\n'
            "No markdown fences. No preamble. No extra keys."
        )
        return [_system(), _msg(_ROLE_USER, user_content)]

    @staticmethod
    def build_explain_decision(
        policy: dict[str, Any],
        input_attrs: dict[str, Any],
        decision: Decision,
    ) -> list[dict[str, str]]:
        """Build messages that ask the LLM to explain a specific decision.

        The LLM is given the policy, the access-request input, and the
        *authoritative* decision produced by ``Guard``.  It is asked only
        to explain *why* — not to re-evaluate.

        Args:
            policy: valid rbacx policy dict used for evaluation.
            input_attrs: original access-request dict
                         (``subject``, ``action``, ``resource``).
            decision: the ``Decision`` returned by ``Guard.evaluate_sync``.
        """
        import json as _json

        outcome = "ALLOWED" if decision.allowed else "DENIED"
        rule_info = f"Matched rule: {decision.rule_id!r}" if decision.rule_id else "No rule matched"
        user_content = (
            "Explain in plain English why the following access request was "
            f"{outcome}.\n\n"
            f"### Policy\n{_json.dumps(policy, indent=2)}\n\n"
            f"### Access request\n{_json.dumps(input_attrs, indent=2)}\n\n"
            f"### Decision\n"
            f"Outcome: {outcome}\n"
            f"{rule_info}\n"
            f"Effect: {decision.effect}\n\n"
            "Write 2-4 sentences. Be specific about which rule applied and why. "
            "Do not output JSON — plain prose only."
        )
        return [_system(), _msg(_ROLE_USER, user_content)]
