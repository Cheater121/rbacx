# AI Policy Authoring System

> **Available in:** `rbacx[ai]` — install with `pip install rbacx[ai]`

The AI Policy Authoring System lets you generate, refine, and understand
rbacx policies using any OpenAI-compatible language model.  You describe
your API in a standard OpenAPI schema and the system produces a valid,
linted rbacx policy that is ready to pass directly to `Guard`.

---

## Installation

```bash
pip install rbacx[ai]
```

This installs `openai>=1.0` and `PyYAML>=6.0` as additional dependencies.

---

## Quick start

```python
import asyncio
from rbacx.ai import AIPolicy
from rbacx.core.engine import Guard

async def main():
    ai = AIPolicy(api_key="sk-...", model="gpt-4o")

    # Generate a policy from an OpenAPI schema
    result = await ai.from_schema("openapi.json", context="SaaS B2B app")

    print(result.dsl)        # ready-to-use policy dict
    print(result.warnings)   # lint issues (empty = clean)

    # Wire directly into Guard
    guard = Guard(result.dsl)

asyncio.run(main())
```

---

## Supported LLM providers

`AIPolicy` accepts any OpenAI-compatible endpoint via `base_url`.

| Provider | Example `base_url` |
|---|---|
| OpenAI (default) | `None` |
| OpenRouter | `"https://openrouter.ai/api/v1"` |
| Ollama (local) | `"http://localhost:11434/v1"` |
| Azure OpenAI | `"https://<resource>.openai.azure.com/openai/deployments/<deployment>"` |

```python
# OpenRouter — access Claude, Gemini, Mistral, etc.
ai = AIPolicy(
    api_key="sk-or-...",
    model="anthropic/claude-3-5-sonnet",
    base_url="https://openrouter.ai/api/v1",
)

# Ollama — fully local, no API key needed
ai = AIPolicy(
    api_key="ollama",   # any non-empty string
    model="llama3",
    base_url="http://localhost:11434/v1",
)
```

---

## `from_schema()` — generate a policy

```python
result = await ai.from_schema(
    schema,           # Path | str | dict  (OpenAPI 3.x or 2.0, JSON or YAML)
    *,
    context="",       # free-form domain hint for the LLM
    safe_mode=True,   # validate → retry → lint pipeline (recommended)
    compile=False,    # also compile the policy (requires rbacx compiler)
    explain=False,    # request per-rule human explanations (extra LLM call)
    raw=False,        # include raw LLM output in result.raw for debugging
)
```

### Parameters

**`schema`** — the API schema to generate a policy for.  Accepted forms:

- `Path` or file-path string pointing to a `.json`, `.yaml`, or `.yml` file
- raw JSON string
- pre-loaded `dict`

OpenAPI 3.x and OpenAPI 2.0 (Swagger) are supported.

**`context`** — optional free-form description of your domain, e.g.
`"multi-tenant SaaS, roles: admin / member / viewer, tenant isolation required"`.
A richer context produces more precise rules.

**`safe_mode`** (default `True`) — runs the full validation pipeline:

```
LLM call → JSON parse → validate (DSL schema) →
  if errors: fix prompt → LLM retry → validate again →
    if still errors: raise ValidationRetryError
lint → warnings
```

Set to `False` only for experimentation; the returned policy may not pass
`validate_policy`.

**`compile`** (default `False`) — compile the policy via the rbacx compiler
and return the result in `result.compiled`.  Raises `PolicyGenerationError`
if the compiler is unexpectedly unavailable.

**`explain`** (default `False`) — make an extra LLM call to produce a
per-rule plain-English explanation.  Result is in `result.explanation`
(`{rule_id: str}`).

**`raw`** (default `False`) — expose the raw LLM response string in
`result.raw`.  Useful for prompt debugging.

### Return value — `PolicyResult`

| Field | Type | Description |
|---|---|---|
| `dsl` | `dict` | Generated policy — pass to `Guard(result.dsl)` |
| `warnings` | `list[Issue]` | Lint issues from `analyze_policy` (empty = clean) |
| `compiled` | `Any \| None` | Compiled policy or `None` |
| `explanation` | `dict[str, str] \| None` | `{rule_id: text}` or `None` |
| `raw` | `str \| None` | Raw LLM output or `None` |

### Example

```python
result = await ai.from_schema(
    "openapi.json",
    context="B2B SaaS. Roles: admin, editor, viewer. Tenant isolation required.",
    explain=True,
    raw=True,
)

for issue in result.warnings:
    print(issue)

for rule_id, text in result.explanation.items():
    print(f"{rule_id}: {text}")

print(result.raw)   # raw LLM JSON
```

---

## `refine_policy()` — iterative refinement

```python
result = await ai.refine_policy(
    feedback,         # str  — natural-language instruction
    *,
    policy=None,      # dict | None — reset session to this policy first
    compile=False,    # compile the refined policy
)
```

`refine_policy` maintains a **persistent conversation history** across calls
so the model remembers all previous feedback.  Each call extends the history
and returns a new `PolicyResult`.

```python
# Start from a generated policy
result = await ai.from_schema("openapi.json")

# Iterative refinement — the model remembers each step
result = await ai.refine_policy("viewers should not be able to delete anything")
result = await ai.refine_policy("editors can update but not create new resources")
result = await ai.refine_policy("admins bypass all restrictions")

# Final policy — ready to use
guard = Guard(result.dsl)
```

### Starting from an explicit policy

Pass `policy=` to reset the session to a specific starting point without
calling `from_schema` first.  This is useful for refining a hand-written or
previously saved policy:

```python
existing_policy = json.loads(Path("my_policy.json").read_text())
result = await ai.refine_policy(
    "add MFA requirement for delete actions on sensitive resources",
    policy=existing_policy,
)
```

### Validation is always on

`refine_policy` always runs the full `safe_mode` pipeline — the refined
policy is validated before being accepted.  If validation fails after two
attempts a `ValidationRetryError` is raised and the session state is **not**
updated (the previous policy is preserved).

---

## `explain_decision()` — human-readable decision explanations

```python
expl = await ai.explain_decision(
    policy=result.dsl,
    input={
        "subject": {
            "id": "user:42",
            "roles": ["viewer"],
            "attrs": {"tenant_id": "acme"},
        },
        "action": "delete",
        "resource": {
            "type": "document",
            "id": "doc:99",
            "attrs": {"tenant_id": "acme", "owner_id": "user:42"},
        },
    },
)

print(expl.decision.allowed)   # True / False  (deterministic — from Guard)
print(expl.decision.rule_id)   # which rule fired
print(expl.human)              # plain-English explanation from LLM
```

### How it works

1. A minimal `Guard(policy)` evaluates the request **deterministically** —
   the LLM never decides the allow/deny outcome.
2. The authoritative `Decision` (including `rule_id`, `effect`, `reason`) is
   passed to the LLM together with the policy and the input.
3. The LLM writes a 2–4 sentence explanation of *why* that decision was
   reached.

This design eliminates hallucination on the security-critical allow/deny
result while still producing useful, readable explanations.

### `input` format

| Key | Type | Required | Description |
|---|---|---|---|
| `subject.id` | `str` | yes | Subject identifier |
| `subject.roles` | `list[str]` | no | Role list (default `[]`) |
| `subject.attrs` | `dict` | no | Subject attributes (default `{}`) |
| `action` | `str` | yes | Action name, e.g. `"read"` |
| `resource.type` | `str` | yes | Resource type |
| `resource.id` | `str \| None` | no | Resource identifier |
| `resource.attrs` | `dict` | no | Resource attributes (default `{}`) |

`explain_decision` is independent of the refinement session — it can be
called without a prior `from_schema`.

---

## `safe_mode` pipeline in detail

```
┌─────────────────────────────────────────────────────────────┐
│ 1. SchemaParser.parse(schema)  →  NormalizedSchema          │
│ 2. PromptBuilder.build_generation(schema, context)          │
│ 3. LLMClient.complete(messages)  →  raw string              │
│ 4. PolicyGenerator._parse_json(raw)  →  dict                │
│ 5. PolicyValidator.validate(dict)                           │
│      ✓ empty errors  →  continue                            │
│      ✗ errors found  →  PromptBuilder.build_fix(…)          │
│                          LLM retry  →  parse  →  validate   │
│                            ✓  →  continue                   │
│                            ✗  →  raise ValidationRetryError │
│ 6. PolicyValidator.lint(dict)  →  warnings                  │
│ 7. (optional) compile                                        │
│ 8. (optional) ExplainGenerator.explain_rules                 │
└─────────────────────────────────────────────────────────────┘
```

---

## Exception reference

| Exception | When raised |
|---|---|
| `SchemaParseError` | Input schema format unrecognised or file unreadable |
| `ValidationRetryError` | Both validation attempts fail in `safe_mode`; carries `.raw` and `.validation_errors` |
| `PolicyGenerationError` | LLM returns empty/non-JSON response; `compile=True` with unavailable compiler; malformed `input` dict |

```python
from rbacx.ai import AIPolicy, ValidationRetryError, PolicyGenerationError

try:
    result = await ai.from_schema("openapi.json")
except ValidationRetryError as e:
    print("Failed after two attempts:")
    for err in e.validation_errors:
        print(f"  {err}")
    print("Last raw output:", e.raw)
except PolicyGenerationError as e:
    print("Generation error:", e)
    if e.cause:
        print("Caused by:", e.cause)
```

---

## Full example: generate, refine, explain

```python
import asyncio
from rbacx.ai import AIPolicy
from rbacx.core.engine import Guard
from rbacx.core.model import Subject, Action, Resource

async def main():
    ai = AIPolicy(api_key="sk-...", model="gpt-4o")

    # 1. Generate from OpenAPI schema
    result = await ai.from_schema(
        "openapi.json",
        context="Document management SaaS. Roles: admin, editor, viewer.",
        explain=True,
    )
    print("Generated policy — warnings:", result.warnings)
    for rule_id, text in result.explanation.items():
        print(f"  {rule_id}: {text}")

    # 2. Refine iteratively
    result = await ai.refine_policy(
        "editors should not be able to delete documents"
    )
    result = await ai.refine_policy(
        "viewers can only read, never write or delete"
    )

    # 3. Wire into Guard
    guard = Guard(result.dsl)

    # 4. Explain a decision
    expl = await ai.explain_decision(
        policy=result.dsl,
        input={
            "subject": {"id": "u1", "roles": ["editor"]},
            "action": "delete",
            "resource": {"type": "document", "id": "d42"},
        },
    )
    verdict = "ALLOWED" if expl.decision.allowed else "DENIED"
    print(f"\nDecision: {verdict}")
    print(f"Rule: {expl.decision.rule_id}")
    print(f"Explanation: {expl.human}")

asyncio.run(main())
```

---

## Runnable demos

Two ready-to-run examples are included under `examples/`:

### `examples/ai_demo/demo.py` — standalone script

A self-contained script that walks through all three AI authoring steps:
generate → refine → explain.  No web framework needed.

```bash
pip install "rbacx[ai]"

# Edit the constants at the top of the file:
#   API_KEY = "sk-..."
#   SCHEMA  = "openapi.json"   # path to your OpenAPI schema
#   MODEL   = "gpt-5.4"

python examples/ai_demo/demo.py
```

### `examples/ai_fastapi_demo/app.py` — live FastAPI integration

Shows how to pass FastAPI's **auto-generated OpenAPI schema** into
`AIPolicy.from_schema()` at startup so the LLM produces a policy that
matches the actual routes — no manual JSON authoring.

```bash
pip install "rbacx[ai]" fastapi uvicorn

export RBACX_AI_API_KEY="sk-..."
export RBACX_AI_MODEL="gpt-5.4"       # optional
export RBACX_AI_BASE_URL=""           # optional, e.g. OpenRouter URL

uvicorn examples.ai_fastapi_demo.app:app --reload --port 8010
```

The app exposes a `GET /policy` endpoint that returns the active policy
and its source (`ai-generated` or `fallback`), making it easy to inspect
what the LLM produced.

If `RBACX_AI_API_KEY` is not set the app starts with a built-in fallback
policy so it remains fully functional without an LLM configured.

**Quick test:**

```bash
curl http://127.0.0.1:8010/policy                                    # inspect generated policy
curl -H "X-Role: viewer" http://127.0.0.1:8010/documents             # 200
curl -H "X-Role: viewer" -X POST http://127.0.0.1:8010/documents     # 403
curl -H "X-Role: editor" -X POST http://127.0.0.1:8010/documents     # 200
curl -H "X-Role: admin"  http://127.0.0.1:8010/reports/monthly       # 200
curl -H "X-Role: viewer" http://127.0.0.1:8010/reports/monthly       # 403
```
