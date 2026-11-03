"""SQLite migrations — backward compatible."""
from __future__ import annotations

import sqlite3

from app.config import DB_PATH, ensure_dirs
from app.services.correlation import init_intel_tables
from app.services.jobs import init_job_tables


def migrate() -> list[str]:
    ensure_dirs()
    applied = []
    with sqlite3.connect(str(DB_PATH)) as conn:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations (id TEXT PRIMARY KEY, applied_at TEXT)"
        )
        def need(mid: str) -> bool:
            return (
                conn.execute("SELECT 1 FROM schema_migrations WHERE id=?", (mid,)).fetchone()
                is None
            )

        def mark(mid: str) -> None:
            from datetime import datetime, timezone

            conn.execute(
                "INSERT INTO schema_migrations (id, applied_at) VALUES (?, ?)",
                (mid, datetime.now(timezone.utc).isoformat()),
            )
            applied.append(mid)

        if need("003_intel"):
            init_intel_tables(conn)
            mark("003_intel")
        if need("004_jobs"):
            init_job_tables(conn)
            mark("004_jobs")
        conn.commit()
    return applied
