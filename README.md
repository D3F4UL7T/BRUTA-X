# BRUTA X

Professional modular cybersecurity desktop toolkit.

**Publisher:** BRUTA Technologies  
**Version:** 1.1.0-phase2  
**Platform:** Windows 10/11 (also runs on Linux with PySide6)  
**Language:** Python 3.12+  
**GUI:** PySide6

## Implemented (Phase 1)

| Module | Status |
|--------|--------|
| Application shell + sidebar navigation | Done |
| Dashboard (real system info + SQLite history) | Done |
| File Analyzer (SHA-256/512, metadata) | Done |
| Password Auditor (local only, never stored) | Done |
| DNS Intelligence | Done (dnspython if installed, else stdlib A/AAAA) |
| Network Scanner (private ranges, auth required) | Done |
| Port Scanner (TCP connect, auth required) | Done |
| Report Center (JSON + HTML from real runs) | Done |
| OSINT IP lookup | Done (public API when network allows) |
| Vulnerability Checks | Not implemented |
| Network Monitor | Not implemented |
| OSINT (username, RDAP, SSL, CT subdomains) | Done |
| Vulnerability assessment (non-destructive) | Done |
| Network monitor (connections / iface stats) | Done |
| AI Assistant (offline + optional remote) | Done |
| PDF reports (reportlab) | Done |

## Install

```bash
cd bruta_x
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

pip install -r requirements.txt
```

## Run

```bash
python main.py
```

## Tests

```bash
python -m unittest tests.test_core -v
```

## Packaging (Windows executable)

```bash
pip install pyinstaller
pyinstaller --noconfirm --windowed --name "BRUTA-X" main.py
```

Optional data folder beside the exe for `data/settings.json` and `data/bruta_x.db`.

## Authorization policy

- Port and network scans require an explicit confirmation checkbox.
- Network scanner defaults to **private/loopback ranges only**.
- No credential theft, malware, stealth scan modes, or exploitation features.

## Project layout

```
bruta_x/
  main.py
  requirements.txt
  README.md
  STATUS.md
  app/
    application.py
    config.py
    database.py
    logging_config.py
    modules/
    services/
    ui/
  tests/
  data/          # created at runtime
```

## License / use

Authorized testing and lab use only. You are responsible for compliance with local law and target authorization.
