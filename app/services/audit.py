"""Persistent audit trail — no secrets."""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from typing import Any

from app.config import DB_PATH, ensure_dirs

BLOCK = ("password", "token", "api_key", "secret", "authorization", "cookie")


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def init_audit_tables(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            resource TEXT,
            result TEXT NOT NULL,
            meta TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
        CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor);
        """
    )


def _scrub_meta(meta: dict[str, Any] | None) -> str:
    import json

    if not meta:
        return "{}"
    clean = {}
    for k, v in meta.items():
        if any(b in str(k).lower() for b in BLOCK):
            clean[k] = "[redacted]"
        else:
            clean[k] = v if not isinstance(v, str) or len(v) < 500 else v[:500]
    return json.dumps(clean, default=str)[:4000]


def audit(
    actor: str,
    action: str,
    resource: str = "",
    result: str = "ok",
    meta: dict[str, Any] | None = None,
) -> int:
    ensure_dirs()
    with sqlite3.connect(str(DB_PATH)) as conn:
        init_audit_tables(conn)
        cur = conn.execute(
            "INSERT INTO audit_log (ts, actor, action, resource, result, meta) VALUES (?,?,?,?,?,?)",
            (_utc(), actor[:120], action[:120], resource[:240], result[:40], _scrub_meta(meta)),
        )
        conn.commit()
        return int(cur.lastrowid)


def list_audit(
    actor: str | None = None,
    action: str | None = None,
    limit: int = 200,
) -> list[dict[str, Any]]:
    with sqlite3.connect(str(DB_PATH)) as conn:
        conn.row_factory = sqlite3.Row
        init_audit_tables(conn)
        sql = "SELECT * FROM audit_log WHERE 1=1"
        args: list[Any] = []
        if actor:
            sql += " AND actor=?"
            args.append(actor)
        if action:
            sql += " AND action LIKE ?"
            args.append(f"%{action}%")
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        return [dict(r) for r in conn.execute(sql, args).fetchall()]
