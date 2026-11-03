# BRUTA X Phase 3 — Implementation Plan

**Baseline:** Phase 1+2 complete, 25/25 tests green (2026-11-03).  
**Git HEAD at audit:** `5fa6e1a` (Phase 2).  
**DB tables:** `events`, `scan_runs`.

## Gaps after Phase 2
- No plugin system
- No cross-module correlation
- No workflow automation
- Visualization limited to tables
- No central job queue / event bus
- No schema migrations helper

## Stages
| Stage | Scope |
|-------|--------|
| A | Audit (this document) |
| B | Plugin architecture + 2 builtin plugins |
| C | Intelligence correlation engine |
| D | Automation / workflow engine |
| E | Visualization data APIs (topology + relationship graphs) |
| F | Backend: jobs, migrations, event bus |
| G | UI pages for plugins, intel graph, automation, tasks |
| H | Tests + docs |

## Safety
Plugins require explicit enable. No auto-run of untrusted code.  
Workflows inherit module authorization gates.  
Correlation never invents edges without evidence.
