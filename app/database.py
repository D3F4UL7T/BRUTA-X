"""SQLite persistence for scan history and reports metadata."""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Iterator

from app.config import DB_PATH, ensure_dirs


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


@contextmanager
def connect() -> Iterator[sqlite3.Connection]:
    ensure_dirs()
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with connect() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                module TEXT NOT NULL,
                level TEXT NOT NULL,
                message TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS scan_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                module TEXT NOT NULL,
                target TEXT,
                status TEXT NOT NULL,
                summary TEXT,
                result_json TEXT
            );
            """
        )


def log_event(module: str, message: str, level: str = "info") -> None:
    with connect() as conn:
        conn.execute(
            "INSERT INTO events (ts, module, level, message) VALUES (?, ?, ?, ?)",
            (_utc(), module, level, message[:2000]),
        )


def list_events(limit: int = 50) -> list[dict[str, Any]]:
    with connect() as conn:
        rows = conn.execute(
            "SELECT id, ts, module, level, message FROM events ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def save_scan_run(
    module: str,
    target: str | None,
    status: str,
    summary: str,
    result: Any,
) -> int:
    with connect() as conn:
        cur = conn.execute(
            "INSERT INTO scan_runs (ts, module, target, status, summary, result_json) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                _utc(),
                module,
                target,
                status,
                summary[:2000],
                json.dumps(result, default=str)[:500_000],
            ),
        )
        return int(cur.lastrowid)


def list_scan_runs(limit: int = 30) -> list[dict[str, Any]]:
    with connect() as conn:
        rows = conn.execute(
            "SELECT id, ts, module, target, status, summary FROM scan_runs "
            "ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_scan_run(run_id: int) -> dict[str, Any] | None:
    with connect() as conn:
        row = conn.execute(
            "SELECT * FROM scan_runs WHERE id = ?", (run_id,)
        ).fetchone()
    return dict(row) if row else None
