
# Security

- Validate policies (JSON Schema 2020-12) before applying.
- Avoid logging sensitive data; apply masking obligations to payloads. When using `DecisionLogger`, prefer `use_default_redactions=True` (if you don't pass explicit `redactions`) and consider `max_env_bytes` to bound payload size.
- Reload policies atomically (HotReloader already re-computes etag).
- Consider step-up auth challenges (e.g., MFA) for high-risk actions.


> **Note (condition depth limit, v1.9.4+):** `eval_condition` limits
> `and`/`or`/`not` nesting to `MAX_CONDITION_DEPTH` (default 50) to prevent a
> maliciously crafted policy from exhausting the Python call stack.  A rule
> whose condition exceeds this limit is treated as a non-match (fail-closed)
> with `reason = "condition_depth_exceeded"`.  Legitimate policies rarely
> exceed 5–10 levels of nesting; the default limit is intentionally generous.


> **Note (condition depth, v1.9.4+):** condition trees loaded from external
> sources are evaluated with a recursion depth limit of `MAX_CONDITION_DEPTH`
> (default 50).  A policy whose `and`/`or`/`not` nesting exceeds this limit
> raises `ConditionDepthError`, which `evaluate()` catches and treats as a
> non-match (fail-closed, `reason = "condition_depth_exceeded"`).  The process
> never crashes with `RecursionError` regardless of policy content.

> **Note (compiled fast-path, v1.9.3+):** the compiled decision path is always
> semantically equivalent to the interpreter for all combining algorithms.
> In particular, a `deny` rule at any resource-specificity level (wildcard,
> type-only, attrs-constrained, or id-specific) correctly overrides a `permit`
> rule at any other level under `deny-overrides`, and the same holds for the
> other algorithms.  If you are upgrading from ≤ 1.9.2, re-evaluate any policy
> that mixes deny and permit rules at different resource-specificity levels to
> confirm the new (correct) behaviour matches your intent.

> **Note (caching):** when using shared/external caches, avoid putting sensitive data into keys/metadata and choose a backend that fits your security requirements. The default in-memory cache is per-process/per-Guard.

> **Note (HTTPPolicySource, v1.9.5+):** `HTTPPolicySource` validates the URL
> scheme against an `allowed_schemes` whitelist and optionally blocks numeric
> private/loopback IP literals (`block_private_ips=True`).  TLS verification,
> timeout, and redirect behaviour are configurable via `verify_ssl`, `timeout`,
> and `allow_redirects`.  See `docs/policy_stores.md` for details.
