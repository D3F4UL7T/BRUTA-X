"""Backward-compatible theme export."""
from app.ui.themes import THEMES, build_stylesheet, list_themes

# default palette constants used by older code
_ACC = THEMES["bruta_dark"]
ACCENT = _ACC["accent"]
BG = _ACC["bg"]
PANEL = _ACC["panel"]
TEXT = _ACC["text"]
STYLESHEET = build_stylesheet("bruta_dark")

__all__ = ["STYLESHEET", "ACCENT", "BG", "PANEL", "TEXT", "build_stylesheet", "list_themes", "THEMES"]
