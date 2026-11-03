# BRUTA X Final Release Report

**Version:** 1.5.0-enterprise  
**Publisher:** BRUTA Technologies  
**Quality pass:** 2026-11-03

## Tests
```bash
export BRUTA_DB_PATH=/tmp/bruta_final.db
python -m unittest discover -s tests -v
```
| Metric | Value |
|--------|-------|
| Total | 53 |
| Passed | 53 |
| Failed | 0 |
| Skipped | 0 |
| Wall time (this host) | ~8s |

## GUI testing
Source integrated; **runtime GUI not executed on headless Linux CI** (PySide6 install historically unavailable). Verify on Windows with `pip install -r requirements.txt && python main.py`.

## Windows build / installer / code signing
- `build_windows.bat` + WINDOWS_BUILD.md provided  
- **Executable not built on this host**  
- **Installer not built**  
- **Code signing not performed**

## Security review summary
- Fixed/confirmed: localhost API policy, webhook SSRF blocks, audit/notify redaction, RBAC deny-default, no secrets in repo  
- Residual: local multi-user depends on OS account protection; plugin code execution is trusted after user enable

## Incomplete / not claimed
- Signed Windows installer  
- Remote license server  
- Full GUI automation suite on CI  
- Cloud collaboration SaaS

## Commands
```bash
pip install -r requirements.txt
python -m unittest discover -s tests -v
python main.py
# Windows:
build_windows.bat
```
