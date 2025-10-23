
# Architecture

```mermaid
flowchart LR
  UI[Frameworks (FastAPI / Flask / Django / DRF / Starlette)] -->|adapters| Core
  Storage[Policy Sources (FS / HTTP(S) / S3)] -->|PolicySource| Core
  Roles[Role Resolver] -->|RoleResolver| Core
  Rel[Relationship Store (Local / SpiceDB / OpenFGA)] -->|RelationshipChecker| Core
  Oblig[Obligations] -->|ObligationChecker| Core
  Telemetry[Decision Logger] -->|DecisionLogSink| Core
  Metrics[Metrics] -->|MetricsSink| Core
  Cache[(Cache)] --- Core
  Reloader[HotReloader] -->|watch & reload| Storage
  Reloader --> Core
  Core[rbacx.core: Guard / Policy / Obligations]
```
