"""Sidebar navigation."""
from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import QFrame, QLabel, QPushButton, QVBoxLayout

NAV = [
    ("dashboard", "Dashboard"),
    ("plugins", "Plugin Center"),
    ("intel", "Intelligence Graph"),
    ("auto", "Automation Studio"),
    ("tasks", "Task Manager"),
    ("analytics", "Security Analytics"),
    ("assets", "Assets"),
    ("compare", "Scan Compare"),
    ("notify", "Notifications"),
    ("search", "Search"),
    ("export", "Export Center"),
    ("projects", "Projects"),
    ("audit", "Audit Trail"),
    ("backup", "Backup"),
    ("license", "License"),
    ("settings", "Settings"),
    ("osint", "OSINT"),
    ("dns", "DNS Intelligence"),
    ("network", "Network Scanner"),
    ("ports", "Port Scanner"),
    ("vuln", "Vulnerability Checks"),
    ("password", "Password Auditor"),
    ("files", "File Analyzer"),
    ("netmon", "Network Monitor"),
    ("ai", "AI Assistant"),
    ("reports", "Reports"),
]


class Sidebar(QFrame):
    navigated = Signal(str)
    about_clicked = Signal()

    def __init__(self):
        super().__init__()
        self.setObjectName("Sidebar")
        self.setFixedWidth(220)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 16, 12, 16)
        layout.setSpacing(4)

        brand = QLabel("BRUTA X")
        brand.setObjectName("Accent")
        brand.setStyleSheet("font-size: 16px; font-weight: 700;")
        layout.addWidget(brand)
        sub = QLabel("BRUTA Technologies")
        sub.setObjectName("Subtitle")
        layout.addWidget(sub)
        layout.addSpacing(12)

        self.buttons: dict[str, QPushButton] = {}
        for key, label in NAV:
            btn = QPushButton(label)
            btn.setObjectName("NavButton")
            btn.setProperty("active", "false")
            btn.clicked.connect(lambda checked=False, k=key: self._click(k))
            layout.addWidget(btn)
            self.buttons[key] = btn

        layout.addStretch(1)
        about = QPushButton("About")
        about.setObjectName("NavButton")
        about.clicked.connect(self.about_clicked.emit)
        layout.addWidget(about)

    def _click(self, key: str) -> None:
        self.set_active(key)
        self.navigated.emit(key)

    def set_active(self, key: str) -> None:
        for k, btn in self.buttons.items():
            btn.setProperty("active", "true" if k == key else "false")
            btn.style().unpolish(btn)
            btn.style().polish(btn)
