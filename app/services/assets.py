"""Asset inventory with explicit authorization scopes."""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from typing import Any

from app.config import DB_PATH, ensure_dirs


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def init_asset_tables(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT NOT NULL,
            value TEXT NOT NULL,
            project TEXT,
            tags TEXT,
            description TEXT,
            owner TEXT,
            authorized INTEGER NOT NULL DEFAULT 0,
            auth_scope TEXT,
            archived INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(type, value)
        );
        CREATE INDEX IF NOT EXISTS idx_assets_value ON assets(value);
        CREATE INDEX IF NOT EXISTS idx_assets_type ON assets(type);
        """
    )


def add_asset(
    type_: str,
    value: str,
    *,
    project: str = "",
    tags: str = "",
    description: str = "",
    owner: str = "",
    authorized: bool = False,
    auth_scope: str = "",
) -> int:
    ensure_dirs()
    now = _utc()
    with sqlite3.connect(str(DB_PATH)) as conn:
        init_asset_tables(conn)
        cur = conn.execute(
            "INSERT OR REPLACE INTO assets "
            "(type, value, project, tags, description, owner, authorized, auth_scope, archived, created_at, updated_at) "
            "VALUES (?,?,?,?,?,?,?,?,0,?,?)",
            (
                type_.strip().lower(),
                value.strip(),
                project,
                tags,
                description,
                owner,
                1 if authorized else 0,
                auth_scope,
                now,
                now,
            ),
        )
        conn.commit()
        return int(cur.lastrowid)


def list_assets(include_archived: bool = False, q: str = "") -> list[dict[str, Any]]:
    ensure_dirs()
    with sqlite3.connect(str(DB_PATH)) as conn:
        conn.row_factory = sqlite3.Row
        init_asset_tables(conn)
        sql = "SELECT * FROM assets WHERE 1=1"
        args: list[Any] = []
        if not include_archived:
            sql += " AND archived=0"
        if q:
            sql += " AND (value LIKE ? OR project LIKE ? OR tags LIKE ? OR description LIKE ?)"
            args.extend([f"%{q}%"] * 4)
        sql += " ORDER BY id DESC LIMIT 500"
        return [dict(r) for r in conn.execute(sql, args).fetchall()]


def is_target_authorized(target: str) -> bool:
    """True only if an asset row explicitly marks authorized=1 matching target."""
    target = target.strip().lower()
    with sqlite3.connect(str(DB_PATH)) as conn:
        init_asset_tables(conn)
        row = conn.execute(
            "SELECT authorized, auth_scope, value FROM assets WHERE archived=0 AND authorized=1"
        ).fetchall()
    for auth, scope, value in row:
        v = (value or "").lower()
        s = (scope or "").lower()
        if target == v or target.endswith(v) or (s and s in target) or (v and v in target):
            return True
    return False


def archive_asset(asset_id: int) -> None:
    with sqlite3.connect(str(DB_PATH)) as conn:
        init_asset_tables(conn)
        conn.execute(
            "UPDATE assets SET archived=1, updated_at=? WHERE id=?",
            (_utc(), asset_id),
        )
        conn.commit()
