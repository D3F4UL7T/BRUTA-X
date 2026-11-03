"""Background job queue with cancellation and SQLite persistence."""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import traceback
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from app.config import DB_PATH, ensure_dirs

JobFunc = Callable[..., Any]


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def init_job_tables(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS jobs (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            started_at TEXT,
            finished_at TEXT,
            error TEXT,
            result_json TEXT,
            cancel_requested INTEGER DEFAULT 0
        );
        """
    )


@dataclass
class Job:
    id: str
    name: str
    status: str = "queued"
    cancel_flag: threading.Event = field(default_factory=threading.Event)


class JobManager:
    def __init__(self, max_workers: int = 4, db_path: Path | None = None):
        self._pool = ThreadPoolExecutor(max_workers=max_workers)
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()
        ensure_dirs()
        self.db_path = Path(db_path or os.environ.get("BRUTA_DB_PATH", str(DB_PATH)))
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(str(self.db_path)) as conn:
            init_job_tables(conn)
            conn.commit()

    def submit(self, name: str, fn: JobFunc, *args: Any, **kwargs: Any) -> str:
        jid = uuid.uuid4().hex[:12]
        job = Job(id=jid, name=name)
        with self._lock:
            self._jobs[jid] = job
        with sqlite3.connect(str(self.db_path)) as conn:
            init_job_tables(conn)
            conn.execute(
                "INSERT INTO jobs (id, name, status, created_at) VALUES (?,?,?,?)",
                (jid, name, "queued", _utc()),
            )
            conn.commit()

        def runner() -> None:
            with sqlite3.connect(str(self.db_path)) as conn:
                conn.execute(
                    "UPDATE jobs SET status=?, started_at=? WHERE id=?",
                    ("running", _utc(), jid),
                )
                conn.commit()
            job.status = "running"
            try:
                if job.cancel_flag.is_set():
                    raise RuntimeError("cancelled before start")
                result = fn(*args, **kwargs, cancel_event=job.cancel_flag)
                status = "cancelled" if job.cancel_flag.is_set() else "completed"
                with sqlite3.connect(str(self.db_path)) as conn:
                    conn.execute(
                        "UPDATE jobs SET status=?, finished_at=?, result_json=? WHERE id=?",
                        (status, _utc(), json.dumps(result, default=str)[:500000], jid),
                    )
                    conn.commit()
                job.status = status
            except Exception as e:
                with sqlite3.connect(str(self.db_path)) as conn:
                    conn.execute(
                        "UPDATE jobs SET status=?, finished_at=?, error=? WHERE id=?",
                        ("failed", _utc(), f"{e}\n{traceback.format_exc()[:2000]}", jid),
                    )
                    conn.commit()
                job.status = "failed"

        self._pool.submit(runner)
        return jid

    def cancel(self, job_id: str) -> bool:
        with self._lock:
            job = self._jobs.get(job_id)
        if not job:
            return False
        job.cancel_flag.set()
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute("UPDATE jobs SET cancel_requested=1 WHERE id=?", (job_id,))
            conn.commit()
        return True

    def list_jobs(self, limit: int = 50) -> list[dict[str, Any]]:
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.row_factory = sqlite3.Row
            init_job_tables(conn)
            rows = conn.execute(
                "SELECT id, name, status, created_at, started_at, finished_at, error "
                "FROM jobs ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    def shutdown(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)
