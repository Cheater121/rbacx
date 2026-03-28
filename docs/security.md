
# Security

- Validate policies (JSON Schema 2020-12) before applying.
- Avoid logging sensitive data; apply masking obligations to payloads. When using `DecisionLogger`, prefer `use_default_redactions=True` (if you don't pass explicit `redactions`) and consider `max_env_bytes` to bound payload size.
- Reload policies atomically (HotReloader already re-computes etag).
- Consider step-up auth challenges (e.g., MFA) for high-risk actions.


> **Note (compiled fast-path, v1.9.3+):** the compiled decision path is always
> semantically equivalent to the interpreter for all combining algorithms.
> In particular, a `deny` rule at any resource-specificity level (wildcard,
> type-only, attrs-constrained, or id-specific) correctly overrides a `permit`
> rule at any other level under `deny-overrides`, and the same holds for the
> other algorithms.  If you are upgrading from ≤ 1.9.2, re-evaluate any policy
> that mixes deny and permit rules at different resource-specificity levels to
> confirm the new (correct) behaviour matches your intent.

> **Note (caching):** when using shared/external caches, avoid putting sensitive data into keys/metadata and choose a backend that fits your security requirements. The default in-memory cache is per-process/per-Guard.
