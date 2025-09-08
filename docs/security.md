
# Security

- Validate policies (JSON Schema 2020-12) before applying.
- Avoid logging sensitive data; apply masking obligations to payloads.
- Reload policies atomically (HotReloader already re-computes etag).
- Consider step-up auth challenges (e.g., MFA) for high-risk actions.
