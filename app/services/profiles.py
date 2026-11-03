"""Local user profiles (preferences only — not multi-user security isolation)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.config import DATA_DIR, ensure_dirs

PROFILES_PATH = DATA_DIR / "profiles.json"


def _load() -> dict[str, Any]:
    ensure_dirs()
    if not PROFILES_PATH.exists():
        data = {
            "active": "default",
            "profiles": {
                "default": {
                    "name": "Default",
                    "theme": "bruta_dark",
                    "dashboard_widgets": ["stats", "recent", "vulns"],
                }
            },
        }
        _save(data)
        return data
    return json.loads(PROFILES_PATH.read_text(encoding="utf-8"))


def _save(data: dict[str, Any]) -> None:
    ensure_dirs()
    PROFILES_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")


def list_profiles() -> list[str]:
    return list(_load()["profiles"].keys())


def get_active() -> dict[str, Any]:
    data = _load()
    return data["profiles"][data["active"]]


def set_active(name: str) -> None:
    data = _load()
    if name not in data["profiles"]:
        raise KeyError(name)
    data["active"] = name
    _save(data)


def upsert_profile(name: str, prefs: dict[str, Any]) -> None:
    data = _load()
    cur = data["profiles"].get(name, {"name": name})
    cur.update(prefs)
    data["profiles"][name] = cur
    _save(data)


def get_theme() -> str:
    return str(get_active().get("theme", "bruta_dark"))
