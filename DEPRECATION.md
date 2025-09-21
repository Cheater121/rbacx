# Deprecation Policy

We follow **Semantic Versioning** and aim to minimize upgrade pain.

## Removal timeframe for deprecated items

Once something is marked `Deprecated`, removal will happen **no earlier** than:
- **two minor releases** (e.g. deprecated in `1.3.x` → earliest removal in `1.5.0`), **or**
- **six (6) months** from the announcement date — **whichever is later**.

## How we announce deprecations

- Runtime `DeprecationWarning` where feasible (with a suggested alternative).
- Changelog entries with **introduced / deprecated / removed** versions.
- Documentation notes and migration hints.
- Where possible, shims/redirected imports kept for the whole grace period.

## Non‑negotiable guarantees

- Stability of **public imports from the root package** `rbacx` (see `API_STABILITY.md`).
  Any change here goes **through deprecation** with a proper transition period.

## Exceptions

Critical security fixes may require immediate behavior changes.
