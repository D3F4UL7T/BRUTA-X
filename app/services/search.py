"""Unified search across assets, scans, intel, notifications."""
from __future__ import annotations

import sqlite3
from typing import Any

from app.config import DB_PATH, ensure_dirs
from app.services.assets import init_asset_tables, list_assets
from app.services.notifications import init_notify_tables


def search(query: str, limit: int = 50) -> dict[str, list[dict[str, Any]]]:
    q = query.strip()
    out: dict[str, list[dict[str, Any]]] = {
        "assets": [],
        "scans": [],
        "entities": [],
        "notifications": [],
    }
    if not q:
        return out
    ensure_dirs()
    out["assets"] = list_assets(q=q)[:limit]
    with sqlite3.connect(str(DB_PATH)) as conn:
        conn.row_factory = sqlite3.Row
        like = f"%{q}%"
        out["scans"] = [
            dict(r)
            for r in conn.execute(
                "SELECT id, ts, module, target, status, summary FROM scan_runs "
                "WHERE target LIKE ? OR summary LIKE ? OR module LIKE ? "
                "ORDER BY id DESC LIMIT ?",
                (like, like, like, limit),
            ).fetchall()
        ]
        try:
            out["entities"] = [
                dict(r)
                for r in conn.execute(
                    "SELECT id, type, value FROM intel_entities WHERE value LIKE ? LIMIT ?",
                    (like, limit),
                ).fetchall()
            ]
        except sqlite3.OperationalError:
            out["entities"] = []
        init_notify_tables(conn)
        out["notifications"] = [
            dict(r)
            for r in conn.execute(
                "SELECT id, ts, category, title FROM notifications "
                "WHERE title LIKE ? OR body LIKE ? ORDER BY id DESC LIMIT ?",
                (like, like, limit),
            ).fetchall()
        ]
    return out
