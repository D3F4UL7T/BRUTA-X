# Release Checklist

- [ ] `python -m unittest discover -s tests`
- [ ] `pip install -r requirements.txt`
- [ ] Launch `python main.py` on Windows 10/11
- [ ] Smoke: DNS, file hash, password, port localhost, asset auth, plugin enable
- [ ] `build_windows.bat` / PyInstaller
- [ ] Code signing (org certificate) — required for distribution, not performed in CI
- [ ] Revoke any GitHub tokens used in development
