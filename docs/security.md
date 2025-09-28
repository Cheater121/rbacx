
# Security

- Validate policies (JSON Schema 2020-12) before applying.
- Avoid logging sensitive data; apply masking obligations to payloads.
- Reload policies atomically (HotReloader already re-computes etag).
- Consider step-up auth challenges (e.g., MFA) for high-risk actions.

> **Note (caching):** when using shared/external caches, avoid putting sensitive data into keys/metadata and choose a backend that fits your security requirements. The default in-memory cache is per-process/per-Guard.
