# Performance

- Keep rules specific (avoid global `"*"` when possible).
- Cache expensive context derivations outside of Guard calls.
- Prefer JSON logging to reduce formatting overhead in hot paths.
- Scale horizontally: stateless `Guard` + shared policy source (file/HTTP/S3).
