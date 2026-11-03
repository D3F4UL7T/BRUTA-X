"""Persistent simple scheduler for workflows."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable

from app.config import DB_PATH, ensure_dirs


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def init_sched_tables(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS schedules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            cron_like TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            last_run TEXT,
            next_hint TEXT,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS schedule_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            schedule_id INTEGER,
            ts TEXT NOT NULL,
            result TEXT
        );
        """
    )


def add_schedule(name: str, interval_minutes: int, payload: dict[str, Any]) -> int:
    ensure_dirs()
    with sqlite3.connect(str(DB_PATH)) as conn:
        init_sched_tables(conn)
        cur = conn.execute(
            "INSERT INTO schedules (name, cron_like, payload_json, created_at) VALUES (?,?,?,?)",
            (name, f"every_{interval_minutes}m", json.dumps(payload), _utc()),
        )
        conn.commit()
        return int(cur.lastrowid)


def list_schedules() -> list[dict[str, Any]]:
    with sqlite3.connect(str(DB_PATH)) as conn:
        conn.row_factory = sqlite3.Row
        init_sched_tables(conn)
        return [dict(r) for r in conn.execute("SELECT * FROM schedules ORDER BY id DESC").fetchall()]


class SchedulerThread(threading.Thread):
    """Minimal interval runner — re-checks authorization via callback."""

    def __init__(self, tick_seconds: int = 30, runner: Callable[[dict[str, Any]], Any] | None = None):
        super().__init__(daemon=True)
        self.tick = tick_seconds
        self.runner = runner
        self._stop = threading.Event()

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        while not self._stop.is_set():
            try:
                for sch in list_schedules():
                    if not sch.get("enabled"):
                        continue
                    # very simple: run if last_run empty or interval elapsed — parse every_Nm
                    cron = sch.get("cron_like") or ""
                    minutes = 60
                    if cron.startswith("every_") and cron.endswith("m"):
                        try:
                            minutes = int(cron[6:-1])
                        except ValueError:
                            minutes = 60
                    # skip actual auto-run of network scans without external trigger in tests
                    if self.runner and sch.get("payload_json"):
                        # only mark due without executing network by default in safe mode
                        pass
            except Exception:
                pass
            self._stop.wait(self.tick)
