# pip install rbacx[ai]
import asyncio
import json

from rbacx.ai import AIPolicy

API_KEY = "sk-..."  # ← insert your API key here
SCHEMA = "openapi.json"  # ← path to your schema (JSON or YAML)
MODEL = "gpt-5.4-mini"  # gpt-5 / claude-3-5-sonnet / llama3 / etc.
BASE_URL = None  # None = OpenAI; for other providers use:
# "https://openrouter.ai/api/v1", etc.


async def main():
    ai = AIPolicy(api_key=API_KEY, model=MODEL, base_url=BASE_URL)

    # ── 1. Generate policy from schema ───────────────────────────────
    print("Generating policy...")
    result = await ai.from_schema(
        SCHEMA,
        context="describe your app here, e.g. 'SaaS B2B, roles: admin/user'",
        explain=True,  # human-readable explanations of rules
        raw=True,  # raw LLM response for debugging
    )

    print("\n── Generated policy ──")
    print(json.dumps(result.dsl, indent=2))

    if result.warnings:
        print("\n── Lint warnings ──")
        for w in result.warnings:
            print(" •", w)

    if result.explanation:
        print("\n── Rule explanations ──")
        for rule_id, text in result.explanation.items():
            print(f" {rule_id}: {text}")

    # ── 2. Refinement ────────────────────────────────────────────────
    print("\nRefining...")
    result = await ai.refine_policy("viewers should only be able to read, never write or delete")
    print("Refined — rules:", [r["id"] for r in result.dsl.get("rules", [])])

    # ── 3. Explain decision ──────────────────────────────────────────
    print("\nExplaining a decision...")
    expl = await ai.explain_decision(
        policy=result.dsl,
        input={
            "subject": {"id": "user:1", "roles": ["viewer"]},
            "action": "delete",
            "resource": {"type": "doc", "id": "doc:42"},
        },
    )
    verdict = "ALLOWED" if expl.decision.allowed else "DENIED"
    print(f"Decision : {verdict}  (rule: {expl.decision.rule_id})")
    print(f"Why      : {expl.human}")

    # ── 4. Save the policy ───────────────────────────────────────────
    with open("policy.json", "w") as f:
        json.dump(result.dsl, f, indent=2)
    print("\nSaved → policy.json")


asyncio.run(main())
