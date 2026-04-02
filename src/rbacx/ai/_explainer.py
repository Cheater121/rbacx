"""Rule-level and decision-level explanation generators."""

import json
from typing import Any

from rbacx.ai._client import LLMClient
from rbacx.ai._prompt import PromptBuilder
from rbacx.ai._result import DecisionExplanation
from rbacx.ai.exceptions import PolicyGenerationError
from rbacx.core.decision import Decision
from rbacx.core.model import Action, Resource, Subject

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_FALLBACK_EXPLANATION = "No explanation available."


def _extract_rule_ids(policy: dict[str, Any]) -> list[str]:
    """Return all rule IDs from a flat or policyset policy dict."""
    ids: list[str] = []
    if "rules" in policy:
        for rule in policy.get("rules") or []:
            rid = rule.get("id")
            if rid:
                ids.append(str(rid))
    for sub in policy.get("policies") or []:
        for rule in sub.get("rules") or []:
            rid = rule.get("id")
            if rid:
                ids.append(str(rid))
    return ids


def _parse_input(input_attrs: dict[str, Any]) -> tuple[Subject, Action, Resource]:
    """Convert an *input_attrs* dict to core model objects.

    Expected format::

        {
            "subject": {
                "id": str,
                "roles": list[str],   # optional, default []
                "attrs": dict,        # optional, default {}
            },
            "action": str,
            "resource": {
                "type": str,
                "id": str | None,    # optional
                "attrs": dict,       # optional, default {}
            },
        }

    Raises:
        PolicyGenerationError: if ``subject``, ``action``, or
            ``resource.type`` are missing or have wrong types.
    """
    if "subject" not in input_attrs or not isinstance(input_attrs["subject"], dict):
        raise PolicyGenerationError(
            "input must contain a 'subject' dict with at least an 'id' field."
        )
    if "action" not in input_attrs or not isinstance(input_attrs["action"], str):
        raise PolicyGenerationError("input must contain an 'action' string (e.g. 'read').")
    resource_raw = input_attrs.get("resource")
    if not isinstance(resource_raw, dict) or not resource_raw.get("type"):
        raise PolicyGenerationError(
            "input must contain a 'resource' dict with at least a 'type' field."
        )

    subj_raw = input_attrs["subject"]
    subject = Subject(
        id=str(subj_raw.get("id", "")),
        roles=list(subj_raw.get("roles") or []),
        attrs=dict(subj_raw.get("attrs") or {}),
    )
    action = Action(name=input_attrs["action"])
    resource = Resource(
        type=str(resource_raw["type"]),
        id=resource_raw.get("id"),
        attrs=dict(resource_raw.get("attrs") or {}),
    )
    return subject, action, resource


# ---------------------------------------------------------------------------
# ExplainGenerator
# ---------------------------------------------------------------------------


class ExplainGenerator:
    """Generates plain-English explanations for every rule in a policy.

    Makes a single LLM call asking for a JSON mapping of
    ``{rule_id: explanation_string}``.  Falls back gracefully when the model
    returns an unexpected format or an incomplete mapping.

    Args:
        client: configured :class:`~rbacx.ai._client.LLMClient` instance.
    """

    def __init__(self, client: LLMClient) -> None:
        self._client = client

    async def explain_rules(self, policy: dict[str, Any]) -> dict[str, str]:
        """Ask the LLM to explain each rule in plain English.

        Makes exactly **one** LLM call.  If the response cannot be parsed as
        a JSON object, or if some rule IDs are missing from the response, the
        missing keys receive :data:`_FALLBACK_EXPLANATION`.

        Args:
            policy: valid rbacx policy dict.

        Returns:
            ``{rule_id: explanation_string}`` for every rule in *policy*.
        """
        rule_ids = _extract_rule_ids(policy)
        messages = PromptBuilder.build_explain_rules(policy)
        raw = await self._client.complete(messages)
        parsed = self._parse_explanation_response(raw)

        # Ensure every rule_id is present; fill gaps with fallback
        return {rid: parsed.get(rid, _FALLBACK_EXPLANATION) for rid in rule_ids}

    @staticmethod
    def _parse_explanation_response(raw: str) -> dict[str, str]:
        """Parse the LLM explanation response into a ``{rule_id: text}`` dict.

        Strips Markdown fences if present and attempts JSON parsing.
        Returns an empty dict on any failure so callers always get a result.
        """
        text = raw.strip()
        if text.startswith("```"):
            first_nl = text.find("\n")
            if first_nl != -1:
                text = text[first_nl + 1 :]
            if text.rstrip().endswith("```"):
                text = text.rstrip()[:-3].rstrip()
        text = text.strip()
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                return {str(k): str(v) for k, v in data.items()}
        except (json.JSONDecodeError, Exception):
            pass
        return {}


# ---------------------------------------------------------------------------
# PolicyExplainer
# ---------------------------------------------------------------------------


class PolicyExplainer:
    """Explains a specific access decision by combining Guard + LLM.

    The access decision is evaluated **deterministically** by a minimal
    :class:`~rbacx.core.engine.Guard` instance — the LLM is never asked to
    decide allow/deny.  The LLM only produces the human-readable narrative.

    Args:
        client: configured :class:`~rbacx.ai._client.LLMClient` instance.
    """

    def __init__(self, client: LLMClient) -> None:
        self._client = client

    async def explain_decision(
        self,
        policy: dict[str, Any],
        input_attrs: dict[str, Any],
    ) -> DecisionExplanation:
        """Evaluate access deterministically, then explain via LLM.

        Args:
            policy: valid rbacx policy dict.
            input_attrs: access-request dict — see :func:`_parse_input` for
                         the expected format.

        Returns:
            :class:`~rbacx.ai._result.DecisionExplanation` with the
            authoritative :class:`~rbacx.core.decision.Decision` and a
            plain-English ``human`` explanation.

        Raises:
            PolicyGenerationError: if *input_attrs* is missing required
                                   fields or has wrong types.
        """
        subject, action, resource = _parse_input(input_attrs)

        from rbacx.core.engine import Guard  # local import — optional dep

        guard = Guard(policy)
        decision: Decision = guard.evaluate_sync(subject, action, resource)

        messages = PromptBuilder.build_explain_decision(policy, input_attrs, decision)
        human = await self._client.complete(messages)

        return DecisionExplanation(decision=decision, human=human.strip())
