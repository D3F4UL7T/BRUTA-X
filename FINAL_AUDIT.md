# BRUTA X Final Audit (Phase 5 start)

**Git:** `69decb7` Phase 4  
**Tests at audit:** 42/42 OK (`BRUTA_DB_PATH` isolation)

## Feature matrix (abbreviated)

| Feature | Status | Tests |
|---------|--------|-------|
| Core modules P1–P2 | Implemented | yes |
| Plugins / correlation / workflows / jobs | Implemented | yes |
| Graph / assets / compare / notify / search / themes | Implemented | yes |
| RBAC multi-role | Missing → Phase 5 | |
| Audit trail | Partial (events) → expand | |
| Project workspaces | Missing → Phase 5 | |
| Local REST API | Missing → Phase 5 | |
| Webhooks SSRF-safe | Missing → Phase 5 | |
| Backup/restore | Missing → Phase 5 | |
| Scheduler persistence | Partial → Phase 5 | |
| License editions | Missing → Phase 5 | |
| Windows signed installer | Not available on Linux CI | docs only |

## Security notes
- Auth checkboxes on active scans exist; asset authorized flag exists
- Secrets redaction in notifications/AI
- Plugins require explicit enable
- Need deny-by-default RBAC + audit + API off by default
