"""Application bootstrap."""
from __future__ import annotations

import sys

from app.config import APP_NAME, ensure_dirs, load_settings
from app.database import init_db
from app.services.migrations import migrate
from app.logging_config import setup_logging


def create_app():
    """Create QApplication + main window. Requires PySide6."""
    from PySide6.QtWidgets import QApplication
    from app.ui.main_window import MainWindow
    from app.ui.themes import build_stylesheet
from app.services.profiles import get_theme

    ensure_dirs()
    init_db()
    migrate()
    log = setup_logging()
    settings = load_settings()
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setStyleSheet(build_stylesheet(get_theme()))
    win = MainWindow(settings=settings, logger=log)
    win.show()
    log.info("BRUTA X UI started")
    return app, win
