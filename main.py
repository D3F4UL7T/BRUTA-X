#!/usr/bin/env python3
"""BRUTA X entry point."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def main() -> int:
    try:
        from app.application import create_app
    except ImportError as e:
        print("Missing dependency:", e)
        print("Install: pip install -r requirements.txt")
        return 1
    app, _win = create_app()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
