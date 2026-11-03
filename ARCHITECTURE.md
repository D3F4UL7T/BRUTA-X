# BRUTA X Architecture

## Layers

- `app/ui` — PySide6 views only
- `app/modules` — pure security operations
- `app/services` — jobs, workflows, correlation, plugins loader helpers, reports
- `app/plugins` — plugin API
- `plugins/` — installed plugin packages (manifest + code)

## Data

SQLite (`data/bruta_x.db`):

- Phase1: `events`, `scan_runs`
- Phase3: `intel_entities`, `intel_relationships`, `jobs`, `schema_migrations`

## Correlation

`ingest_scan_result` creates entities/edges only from concrete evidence fields (DNS A/AAAA, CT subs, TLS CN, vuln findings, ASN).

## Jobs

`JobManager` persists status transitions and supports cancel flags for cooperative cancellation.
