# ReBAC Overview

RBACX supports relationship-based authorization via the `rel` policy condition and a pluggable `RelationshipChecker` port.

## Providers

* **Local ReBAC** (built-in; no extra)
* **OpenFGA** (optional extra) — Zanzibar-style relationship tuples and a `Check` API for testing whether a user has a relation to an object.
* **SpiceDB/Authzed** (optional extra) — open-source Zanzibar-inspired permissions database; models **relationships** (subject–relation–resource) and exposes permission/relationship checks.

## How it fits

* Use `rel` in policies to assert that the **subject** holds a given **relation** to the **resource** (e.g., `"owner"`, `"editor"`).
* Configure `Guard(..., relationship_checker=...)` with your chosen provider (local, OpenFGA, or SpiceDB/Authzed).
* **Fail-closed:** if no `RelationshipChecker` is configured, `rel` conditions evaluate to `false`.

See provider-specific pages for setup and examples.
