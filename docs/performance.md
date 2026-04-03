# Performance

- Keep rules specific (avoid global `"*"` when possible).
- The compiled fast-path is enabled automatically; it is always equivalent to
  the authoritative interpreter for all combining algorithms (`deny-overrides`,
  `permit-overrides`, `first-applicable`).  No configuration is required.
- Cache expensive context derivations outside of Guard calls.
- Use **smart sampling** to reduce log volume while keeping critical events (`deny`, `permit_with_obligations`).
- Bound log record size with `max_env_bytes`; prefer `as_json=True` for cheaper formatting.
- Prefer JSON logging to reduce formatting overhead in hot paths.
- Scale horizontally: stateless `Guard` + shared policy source (file/HTTP/S3).
- **Use `evaluate_batch_async` / `evaluate_batch_sync`** when you need to check
  multiple actions for the same user at once (e.g., rendering a UI with
  enabled/disabled buttons). Requests run concurrently via `asyncio.gather`,
  so the wall-clock time equals the slowest individual check rather than the
  sum of all checks.
