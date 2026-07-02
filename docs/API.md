# API

Base path: `/api/v1`

## Auth

- `POST /auth/register`
- `POST /auth/login`
- `POST /auth/logout`
- `GET /auth/me`

## Projects

- `GET /projects`
- `POST /projects`
- `GET /projects/{project_id}`
- `PATCH /projects/{project_id}`
- `DELETE /projects/{project_id}`
- `GET /projects/{project_id}/dashboard`

Project creation requires `authorization_confirmed=true`. Domains are normalized, validated, and checked against internal-target rules before persistence.

## Scans

- `POST /projects/{project_id}/scans`
- `GET /projects/{project_id}/scans`
- `GET /scans/{scan_id}`
- `GET /scans/{scan_id}/logs`
- `GET /scans/{scan_id}/changes`
- `POST /scans/{scan_id}/cancel`
- `POST /scans/{scan_id}/retry`

Manual scans are queued with FastAPI background tasks and use conservative scanner defaults.

## Assets And Findings

- `GET /projects/{project_id}/assets`
- `GET /projects/{project_id}/findings`
- `GET /projects/{project_id}/changes`
- `GET /assets/{asset_id}`
- `GET /findings/{finding_id}`
- `PATCH /findings/{finding_id}/status`
- `GET /findings/{finding_id}/notes`
- `POST /findings/{finding_id}/notes`

## Scheduled Jobs

- `GET /projects/{project_id}/schedule`
- `PATCH /projects/{project_id}/schedule`
- `POST /scheduled-jobs/run-due` admin only

## Audit Logs

- `GET /audit-logs` admin only

## Planned Phase 3-5 APIs

- Email/webhook notification settings
- Team and organization administration
