@echo off
setlocal
python -m pip install -r requirements.txt pyinstaller
python -m unittest tests.test_core tests.test_phase2 tests.test_phase3 tests.test_phase4
if errorlevel 1 (
  echo Tests failed — aborting package
  exit /b 1
)
pyinstaller --noconfirm --windowed --name BRUTA-X --collect-all PySide6 main.py
echo Output under dist\BRUTA-X
