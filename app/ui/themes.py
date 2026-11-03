"""Theme engine — multiple named stylesheets."""
from __future__ import annotations

THEMES: dict[str, dict[str, str]] = {
    "bruta_dark": {
        "bg": "#1a1b1e",
        "panel": "#2b2d31",
        "panel2": "#232428",
        "text": "#e8e8e8",
        "muted": "#9aa0a6",
        "accent": "#39FF14",
        "border": "#3a3c42",
        "danger": "#ED4245",
    },
    "graphite": {
        "bg": "#121212",
        "panel": "#1e1e1e",
        "panel2": "#181818",
        "text": "#f0f0f0",
        "muted": "#888888",
        "accent": "#7CFF6B",
        "border": "#333333",
        "danger": "#FF5555",
    },
    "midnight_green": {
        "bg": "#0b1410",
        "panel": "#122018",
        "panel2": "#0f1a14",
        "text": "#e6ffef",
        "muted": "#7aa890",
        "accent": "#00E676",
        "border": "#1e3a2c",
        "danger": "#FF6E6E",
    },
    "ocean_blue": {
        "bg": "#0b1220",
        "panel": "#141e30",
        "panel2": "#101828",
        "text": "#e8f1ff",
        "muted": "#8aa0c0",
        "accent": "#4FC3F7",
        "border": "#24344d",
        "danger": "#EF5350",
    },
    "high_contrast": {
        "bg": "#000000",
        "panel": "#111111",
        "panel2": "#0a0a0a",
        "text": "#FFFFFF",
        "muted": "#CCCCCC",
        "accent": "#00FF00",
        "border": "#FFFFFF",
        "danger": "#FF0000",
    },
}


def build_stylesheet(theme_id: str) -> str:
    c = THEMES.get(theme_id, THEMES["bruta_dark"])
    return f"""
QWidget {{ background-color: {c['bg']}; color: {c['text']};
  font-family: "Segoe UI", "Ubuntu", sans-serif; font-size: 13px; }}
QMainWindow, QDialog {{ background-color: {c['bg']}; }}
QFrame#Sidebar {{ background-color: {c['panel']}; border-right: 1px solid {c['border']}; }}
QPushButton#NavButton {{ background: transparent; color: {c['text']}; text-align: left;
  padding: 10px 14px; border: none; border-radius: 6px; }}
QPushButton#NavButton:hover {{ background-color: {c['panel2']}; }}
QPushButton#NavButton[active="true"] {{ background-color: {c['panel2']}; color: {c['accent']};
  border-left: 3px solid {c['accent']}; }}
QPushButton#Primary {{ background-color: {c['panel2']}; color: {c['accent']};
  border: 1px solid {c['accent']}; border-radius: 6px; padding: 8px 14px; }}
QLineEdit, QPlainTextEdit, QSpinBox, QComboBox {{ background-color: {c['panel2']};
  border: 1px solid {c['border']}; border-radius: 4px; padding: 6px 8px; color: {c['text']}; }}
QTableWidget {{ background-color: {c['panel2']}; gridline-color: {c['border']};
  border: 1px solid {c['border']}; }}
QHeaderView::section {{ background-color: {c['panel']}; color: {c['muted']}; padding: 6px; border: none; }}
QLabel#Title {{ font-size: 18px; font-weight: 600; color: {c['text']}; }}
QLabel#Subtitle {{ color: {c['muted']}; }}
QLabel#Accent {{ color: {c['accent']}; }}
QStatusBar {{ background: {c['panel']}; color: {c['muted']}; }}
QGraphicsView {{ background: {c['panel2']}; border: 1px solid {c['border']}; }}
"""


def list_themes() -> list[str]:
    return list(THEMES.keys())
