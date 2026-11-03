"""Dark graphite theme with neon-green accent."""
from __future__ import annotations

ACCENT = "#39FF14"
BG = "#1a1b1e"
PANEL = "#2b2d31"
PANEL2 = "#232428"
TEXT = "#e8e8e8"
MUTED = "#9aa0a6"
DANGER = "#ED4245"
BORDER = "#3a3c42"

STYLESHEET = f"""
QWidget {{
    background-color: {BG};
    color: {TEXT};
    font-family: "Segoe UI", "Ubuntu", sans-serif;
    font-size: 13px;
}}
QMainWindow, QDialog {{
    background-color: {BG};
}}
QFrame#Sidebar {{
    background-color: {PANEL};
    border-right: 1px solid {BORDER};
}}
QPushButton#NavButton {{
    background-color: transparent;
    color: {TEXT};
    text-align: left;
    padding: 10px 14px;
    border: none;
    border-radius: 6px;
}}
QPushButton#NavButton:hover {{
    background-color: {PANEL2};
}}
QPushButton#NavButton[active="true"] {{
    background-color: #1f2a1f;
    color: {ACCENT};
    border-left: 3px solid {ACCENT};
}}
QPushButton#Primary {{
    background-color: #1f3d1f;
    color: {ACCENT};
    border: 1px solid {ACCENT};
    border-radius: 6px;
    padding: 8px 14px;
}}
QPushButton#Primary:hover {{
    background-color: #274d27;
}}
QPushButton#Primary:disabled {{
    color: {MUTED};
    border-color: {BORDER};
    background-color: {PANEL2};
}}
QLineEdit, QPlainTextEdit, QSpinBox, QComboBox {{
    background-color: {PANEL2};
    border: 1px solid {BORDER};
    border-radius: 4px;
    padding: 6px 8px;
    selection-background-color: #2a4a2a;
}}
QTableWidget {{
    background-color: {PANEL2};
    gridline-color: {BORDER};
    border: 1px solid {BORDER};
}}
QHeaderView::section {{
    background-color: {PANEL};
    color: {MUTED};
    padding: 6px;
    border: none;
    border-bottom: 1px solid {BORDER};
}}
QProgressBar {{
    border: 1px solid {BORDER};
    border-radius: 4px;
    text-align: center;
    background: {PANEL2};
}}
QProgressBar::chunk {{
    background-color: {ACCENT};
}}
QLabel#Title {{
    font-size: 18px;
    font-weight: 600;
    color: {TEXT};
}}
QLabel#Subtitle {{
    color: {MUTED};
}}
QLabel#Accent {{
    color: {ACCENT};
}}
QStatusBar {{
    background: {PANEL};
    color: {MUTED};
}}
"""
