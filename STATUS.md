# BRUTA X Status — Phase 4 (Professional Edition)

**Version:** 1.3.0-phase4

## Tests
```bash
export BRUTA_DB_PATH=/tmp/bruta_test.db   # optional isolation
python -m unittest tests.test_core tests.test_phase2 tests.test_phase3 tests.test_phase4 -v
```
**Result on build host:** 42/42 OK

## Phase 4 delivered
- Interactive graph (QGraphicsView; requires PySide6 at runtime)
- Themes (5) + local profiles
- Assets + authorization scope
- Scan comparison
- Notifications (secret scrubbing)
- Unified search
- Export JSON/HTML/CSV (+ PDF if reportlab)
- Windows build script/docs
- DB migrations 005/006
- BRUTA_DB_PATH override for tests

## Limits
- Graph needs PySide6 display environment
- Windows exe not produced on this Linux CI host
- Dashboard widgets are data-backed lists, not a full drag-layout editor
- No claimed multi-user security isolation
