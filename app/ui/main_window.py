"""Main window shell with sidebar navigation."""
from __future__ import annotations

import logging
from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QStackedWidget,
    QStatusBar,
    QVBoxLayout,
    QWidget,
)

from app import __version__
from app.config import APP_NAME, PUBLISHER, save_settings
from app.services.profiles import get_theme
from app.ui.themes import build_stylesheet
from app.ui.sidebar import Sidebar
from app.ui.graph_view import InteractiveGraphPage
from app.ui.pages import (
    DashboardPage,
    DnsPage,
    FileAnalyzerPage,
    NetworkScanPage,
    PasswordPage,
    PortScanPage,
    PlaceholderPage,
    ReportsPage,
    OsintPage,
    VulnPage,
    NetMonPage,
    AIPage,
    PluginCenterPage,
    IntelGraphPage,
    AutomationPage,
    TaskManagerPage,
    AnalyticsPage,
    AssetsPage,
    ComparePage,
    NotifyPage,
    SearchPage,
    ExportCenterPage,
)


class MainWindow(QMainWindow):
    def __init__(self, settings: dict[str, Any], logger: logging.Logger):
        super().__init__()
        self.settings = settings
        self.log = logger
        self.setWindowTitle(f"{APP_NAME} · {PUBLISHER}")
        try:
            self.setStyleSheet(build_stylesheet(get_theme()))
        except Exception:
            pass
        self.resize(int(settings.get("window_width", 1280)), int(settings.get("window_height", 800)))

        root = QWidget()
        self.setCentralWidget(root)
        layout = QHBoxLayout(root)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self.sidebar = Sidebar()
        layout.addWidget(self.sidebar)

        right = QVBoxLayout()
        right.setContentsMargins(16, 12, 16, 12)
        self.title = QLabel("Dashboard")
        self.title.setObjectName("Title")
        right.addWidget(self.title)

        self.stack = QStackedWidget()
        right.addWidget(self.stack, 1)
        layout.addLayout(right, 1)

        # pages
        self.pages = {
            "dashboard": DashboardPage(),
            "assets": AssetsPage(),
            "compare": ComparePage(),
            "notify": NotifyPage(),
            "search": SearchPage(),
            "export": ExportCenterPage(),
            "plugins": PluginCenterPage(),
            "intel": InteractiveGraphPage() if InteractiveGraphPage is not None else IntelGraphPage(),
            "auto": AutomationPage(),
            "tasks": TaskManagerPage(),
            "analytics": AnalyticsPage(),
            "osint": OsintPage(),
            "dns": DnsPage(),
            "network": NetworkScanPage(),
            "ports": PortScanPage(),
            "vuln": VulnPage(),
            "password": PasswordPage(),
            "files": FileAnalyzerPage(),
            "netmon": NetMonPage(),
            "ai": AIPage(),
            "reports": ReportsPage(),
        }
        self._keys = list(self.pages.keys())
        for key in self._keys:
            self.stack.addWidget(self.pages[key])

        self.sidebar.navigated.connect(self._on_nav)
        self.sidebar.about_clicked.connect(self._about)

        sb = QStatusBar()
        self.setStatusBar(sb)
        sb.showMessage(f"{APP_NAME} {__version__} · ready")

        start = settings.get("last_module", "dashboard")
        if start in self.pages:
            self.sidebar.set_active(start)
            self._on_nav(start)

    def _on_nav(self, key: str) -> None:
        if key not in self.pages:
            return
        idx = self._keys.index(key)
        self.stack.setCurrentIndex(idx)
        titles = {
            "dashboard": "Dashboard",
            "plugins": "Plugin Center",
            "intel": "Intelligence Graph",
            "auto": "Automation Studio",
            "tasks": "Task Manager",
            "analytics": "Security Analytics",
            "export": "Export Center",
            "search": "Search",
            "notify": "Notifications",
            "compare": "Scan Compare",
            "assets": "Assets",
            "osint": "OSINT",
            "dns": "DNS Intelligence",
            "network": "Network Scanner",
            "ports": "Port Scanner",
            "vuln": "Vulnerability Checks",
            "password": "Password Auditor",
            "files": "File Analyzer",
            "netmon": "Network Monitor",
            "ai": "AI Assistant",
            "reports": "Report Center",
        }
        self.title.setText(titles.get(key, key))
        self.settings["last_module"] = key
        save_settings(self.settings)
        page = self.pages[key]
        if hasattr(page, "on_show"):
            page.on_show()
        self.statusBar().showMessage(f"{titles.get(key, key)} · ready")

    def _about(self) -> None:
        QMessageBox.about(
            self,
            f"About {APP_NAME}",
            f"<b>{APP_NAME}</b><br>"
            f"Version {__version__}<br>"
            f"Publisher: {PUBLISHER}<br><br>"
            "Professional modular cybersecurity toolkit for authorized use.<br>"
            "Phase 1: shell + DNS, files, passwords, network/port scanners, reports.",
        )

    def closeEvent(self, event) -> None:  # noqa: N802
        self.settings["window_width"] = self.width()
        self.settings["window_height"] = self.height()
        save_settings(self.settings)
        super().closeEvent(event)
