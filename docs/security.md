
# Security

- Validate policies (JSON Schema 2020-12) before applying.
- Avoid logging sensitive data; apply masking obligations to payloads. When using `DecisionLogger`, prefer `use_default_redactions=True` (if you don't pass explicit `redactions`) and consider `max_env_bytes` to bound payload size.
- Reload policies atomically (HotReloader already re-computes etag).
- Consider step-up auth challenges (e.g., MFA) for high-risk actions.

> **Note (caching):** when using shared/external caches, avoid putting sensitive data into keys/metadata and choose a backend that fits your security requirements. The default in-memory cache is per-process/per-Guard.
