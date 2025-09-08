
# Architecture

```mermaid
flowchart LR
  UI[Frameworks] -->|adapters| Core
  Storage[Policy Sources] --> Core
  Telemetry[Decision Logger] --> Core
  Core[rbacx.core: Guard/Policy/Obligations]
```
