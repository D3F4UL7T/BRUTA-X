# BRUTA X Local API

Disabled by default. Start via `start_api("127.0.0.1", 8765)` after login token issued.

## Auth
`Authorization: Bearer <session_token>`

## Endpoints
- `GET /api/v1/status` — public
- `GET /api/v1/projects` — scans.view
- `GET /api/v1/assets` — assets.view
- `GET /api/v1/scans` — scans.view
- `GET /api/v1/tasks` — scans.view
- `POST /api/v1/tasks/{id}/cancel` — workflows.run
