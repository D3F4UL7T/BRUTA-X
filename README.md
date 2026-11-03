# BRUTA X

**Publisher:** BRUTA Technologies  
**Version:** 1.5.0-enterprise  
**Platform:** Windows 10/11 (also runs on Linux with dependencies)  
**Stack:** Python 3.12+ · PySide6 · SQLite

Professional modular cybersecurity desktop toolkit for **authorized** assessment, OSINT, reporting, and local enterprise controls.

## Features (implemented)

### Core assessments
- File analyzer (SHA-256/512, metadata)
- Password auditor (local only — never stored or logged)
- DNS intelligence
- Port scanner (TCP connect, auth required)
- Private-network reachability (public ranges blocked by default)
- Vulnerability checks (headers, TLS, cookies, listings — non-destructive)
- Network connection monitor
- OSINT: IP geo, username presence, RDAP, SSL cert, CT subdomains

### Platform
- Plugin system (explicit enable; allow-listed permissions)
- Intelligence correlation (evidence-backed graph data)
- Interactive graph (QGraphicsView when PySide6 available)
- Workflows + job queue
- Assets with authorization scope
- Scan comparison, notifications, unified search
- Themes (5) + local profiles
- Exports: JSON, HTML, CSV, PDF (reportlab optional)

### Enterprise
- RBAC: OWNER / ADMINISTRATOR / ANALYST / VIEWER (PBKDF2 passwords)
- Audit trail (secret redaction)
- Project workspaces + membership
- Local REST API (**disabled by default**, localhost only)
- Webhooks (HTTPS + SSRF protections)
- Backup / restore with integrity hash
- Offline edition configuration (Community / Professional / Enterprise)

## Install

```bash
cd bruta_x
python -m venv .venv
# Windows: .venv\Scripts\activate
source .venv/bin/activate
pip install -r requirements.txt
```

## Run

```bash
python main.py
```

First run may create `data/owner_bootstrap.txt` with the initial owner password — change it.

## Test

```bash
export BRUTA_DB_PATH=/tmp/bruta_test.db   # optional isolation
python -m unittest discover -s tests -v
```

## Windows package

See [WINDOWS_BUILD.md](WINDOWS_BUILD.md) and `build_windows.bat`.

Code signing is an organizational release step — not performed in CI.

## Security

See [SECURITY.md](SECURITY.md). Active scans require explicit authorization. Do not target systems without permission.

## Documentation

| Doc | Purpose |
|-----|---------|
| [USER_GUIDE.md](USER_GUIDE.md) | Operator basics |
| [ENTERPRISE_GUIDE.md](ENTERPRISE_GUIDE.md) | RBAC / projects / API |
| [API_DOCUMENTATION.md](API_DOCUMENTATION.md) | Local REST API |
| [BACKUP_RECOVERY.md](BACKUP_RECOVERY.md) | Backup/restore |
| [LICENSING.md](LICENSING.md) | Editions |
| [FINAL_QUALITY_AUDIT.md](FINAL_QUALITY_AUDIT.md) | Quality audit |
| [FINAL_RELEASE_REPORT.md](FINAL_RELEASE_REPORT.md) | Release honesty report |
| [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md) | Ship checklist |

## License / use

Authorized testing and lab use only. You are responsible for compliance with law and target authorization.
