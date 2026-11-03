# BRUTA X — Status

## Environment notes (build host)

- Python 3.12 available.
- PySide6 / dnspython could **not** be installed on the build host due to PyPI proxy 502 errors.
- Core logic and unit tests run without GUI packages.
- GUI requires `pip install -r requirements.txt` on a machine with working PyPI access.

## Feature checklist

### Done and tested (logic)

- [x] Config + settings persistence paths
- [x] SQLite events + scan_runs
- [x] File hashing (chunked SHA-256/512)
- [x] Password strength auditor (no storage)
- [x] DNS query (stdlib fallback; dnspython when present)
- [x] Port scanner TCP connect with auth gate
- [x] Network private-range gate + interface listing
- [x] Report JSON/HTML export from DB
- [x] Unit tests (`tests/test_core.py`)

### Implemented in source (needs PySide6 to run UI)

- [x] Main window, sidebar, stacked pages, theme
- [x] Dashboard / File / Password / DNS / Port / Network / OSINT / Reports pages

### Incomplete

- [ ] Vulnerability scanner module
- [ ] Network monitor module
- [ ] AI assistant module
- [ ] End-to-end GUI automation tests
- [ ] Signed Windows installer

## Commands

```bash
python -m unittest tests.test_core -v
python main.py   # after pip install -r requirements.txt
```
