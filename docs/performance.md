# Performance

- Keep rules specific (avoid global `"*"` when possible).
- Cache expensive context derivations outside of Guard calls.
- Use **smart sampling** to reduce log volume while keeping critical events (`deny`, `permit_with_obligations`).
- Bound log record size with `max_env_bytes`; prefer `as_json=True` for cheaper formatting.
- Prefer JSON logging to reduce formatting overhead in hot paths.
- Scale horizontally: stateless `Guard` + shared policy source (file/HTTP/S3).
