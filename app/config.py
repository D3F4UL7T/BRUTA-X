"""Application configuration and persistent settings."""
from __future__ import annotations

import json
from pathlib import Path

APP_NAME = "BRUTA X"
APP_VERSION = "1.0.0-phase1"
PUBLISHER = "BRUTA Technologies"

# Paths relative to user data / project
PACKAGE_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PACKAGE_ROOT / "data"
SETTINGS_PATH = DATA_DIR / "settings.json"
DB_PATH = DATA_DIR / "bruta_x.db"
LOG_DIR = DATA_DIR / "logs"

DEFAULT_SETTINGS = {
    "theme": "dark_graphite",
    "accent": "#39FF14",
    "window_width": 1280,
    "window_height": 800,
    "last_module": "dashboard",
    "dns_timeout_sec": 8,
    "port_timeout_sec": 1.5,
    "port_max_concurrency": 64,
    "network_max_hosts": 256,
    "authorized_private_only": True,
}


def ensure_dirs() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)


def load_settings() -> dict:
    ensure_dirs()
    if not SETTINGS_PATH.exists():
        save_settings(DEFAULT_SETTINGS.copy())
        return DEFAULT_SETTINGS.copy()
    try:
        data = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
        merged = DEFAULT_SETTINGS.copy()
        merged.update({k: v for k, v in data.items() if k in DEFAULT_SETTINGS})
        return merged
    except Exception:
        return DEFAULT_SETTINGS.copy()


def save_settings(settings: dict) -> None:
    ensure_dirs()
    SETTINGS_PATH.write_text(json.dumps(settings, indent=2), encoding="utf-8")
