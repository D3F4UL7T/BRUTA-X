"""Notification center — no secrets in payloads."""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from typing import Any

from app.config import DB_PATH, ensure_dirs

SENSITIVE = ("password", "token", "api_key", "secret", "authorization")


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def init_notify_tables(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            category TEXT NOT NULL,
            title TEXT NOT NULL,
            body TEXT NOT NULL,
            read INTEGER NOT NULL DEFAULT 0,
            archived INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_notif_read ON notifications(read);
        """
    )


def _scrub(text: str) -> str:
    low = text.lower()
    for s in SENSITIVE:
        if s in low:
            return "[redacted notification content]"
    return text[:2000]


def notify(category: str, title: str, body: str) -> int:
    ensure_dirs()
    with sqlite3.connect(str(DB_PATH)) as conn:
        init_notify_tables(conn)
        cur = conn.execute(
            "INSERT INTO notifications (ts, category, title, body) VALUES (?,?,?,?)",
            (_utc(), category, _scrub(title), _scrub(body)),
        )
        conn.commit()
        return int(cur.lastrowid)


def list_notifications(
    unread_only: bool = False, category: str | None = None, limit: int = 100
) -> list[dict[str, Any]]:
    with sqlite3.connect(str(DB_PATH)) as conn:
        conn.row_factory = sqlite3.Row
        init_notify_tables(conn)
        sql = "SELECT * FROM notifications WHERE archived=0"
        args: list[Any] = []
        if unread_only:
            sql += " AND read=0"
        if category:
            sql += " AND category=?"
            args.append(category)
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        return [dict(r) for r in conn.execute(sql, args).fetchall()]


def mark_read(nid: int) -> None:
    with sqlite3.connect(str(DB_PATH)) as conn:
        init_notify_tables(conn)
        conn.execute("UPDATE notifications SET read=1 WHERE id=?", (nid,))
        conn.commit()
