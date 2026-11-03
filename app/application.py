"""Application bootstrap."""
from __future__ import annotations

import sys

from app.config import APP_NAME, ensure_dirs, load_settings
from app.database import init_db
from app.logging_config import setup_logging


def create_app():
    """Create QApplication + main window. Requires PySide6."""
    from PySide6.QtWidgets import QApplication
    from app.ui.main_window import MainWindow
    from app.ui.theme import STYLESHEET

    ensure_dirs()
    init_db()
    log = setup_logging()
    settings = load_settings()
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setStyleSheet(STYLESHEET)
    win = MainWindow(settings=settings, logger=log)
    win.show()
    log.info("BRUTA X UI started")
    return app, win
