# Architecture

SurfaceWatch is split into a Next.js frontend, FastAPI backend, PostgreSQL database, Redis queue/cache layer, and scanner modules.

```mermaid
flowchart TB
  Web["Next.js App"] --> Auth["Auth API"]
  Web --> Projects["Project APIs"]
  Web --> Dashboard["Dashboard APIs"]
  Projects --> DB["PostgreSQL"]
  Dashboard --> DB
  Auth --> DB
  ScanAPI["Scan API"] --> Jobs["Background Jobs"]
  Jobs --> Scanner["Scanner Engine"]
  Scanner --> DB
  Scanner --> Internet["Authorized Public Assets"]
```

The backend owns authorization, persistence, validation, scan orchestration, risk scoring, change detection, report generation, and notification creation. The frontend focuses on workflow, filtering, visualization, and clear safety messaging.
