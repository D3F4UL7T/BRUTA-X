# Windows Build

```bat
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt pyinstaller
python -m unittest tests.test_core tests.test_phase2 tests.test_phase3 tests.test_phase4
build_windows.bat
```

**Note:** Executable is only verified after you run PyInstaller on Windows. CI hosts without PySide6 cannot validate the GUI binary.
