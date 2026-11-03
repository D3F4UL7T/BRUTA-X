# BRUTA X — Status (Phase 2)

**Version:** 1.1.0-phase2

## Phase 1 regression

- Core unit tests: password, file hash, DNS, ports, network policy, DB/reports — retained.

## Phase 2 added

| Area | Status | Notes |
|------|--------|-------|
| OSINT username / RDAP / SSL / CT subs / IP | Done | Public sources; graceful failures |
| Vulnerability assessment | Done | Non-destructive headers/TLS/cookies/listing |
| Network monitor | Done | ss/netstat + /proc/net/dev when available |
| AI assistant | Done | Offline default; optional remote; sanitizes secrets |
| PDF reports | Done | Requires `reportlab` |
| UI pages for vuln/netmon/AI/OSINT modes | Done | Needs PySide6 at runtime |

## Tests

```bash
python -m unittest tests.test_core tests.test_phase2 -v
```

## Incomplete / limits

- Topology graph visualization (data only; no canvas graph yet)
- GUI integration tests (no display on CI host)
- Signed installer
- PySide6 may be unavailable on restricted build hosts

## Security policy (unchanged)

No credential theft, malware, exploitation, stealth scanning, or public-range scans by default.
