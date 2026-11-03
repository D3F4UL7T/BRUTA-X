# BRUTA X Status — Phase 3

**Version:** 1.2.0-phase3

## Tests
Run: `python -m unittest tests.test_core tests.test_phase2 tests.test_phase3 -v`

## Phase 3
- Plugin architecture + 2 builtins
- Correlation engine
- Workflows
- Jobs / migrations / event bus
- Visualization data (no fake nodes)
- UI sections added

## Limits
- Topology is data-driven lists/JSON (no GPU canvas graph library bundled)
- PySide6 may be missing on restricted CI hosts
- No signed Windows installer
