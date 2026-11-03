"""SQLite migrations — backward compatible."""
from __future__ import annotations

import sqlite3

from app.config import DB_PATH, ensure_dirs
from app.services.correlation import init_intel_tables
from app.services.jobs import init_job_tables
from app.services.assets import init_asset_tables
from app.services.notifications import init_notify_tables
from app.services.rbac import init_rbac_tables
from app.services.audit import init_audit_tables
from app.services.projects import init_project_tables
from app.services.scheduler import init_sched_tables


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
        if need("005_assets"):
            init_asset_tables(conn)
            mark("005_assets")
        if need("006_notifications"):
            init_notify_tables(conn)
            mark("006_notifications")
        if need("007_rbac"):
            init_rbac_tables(conn)
            mark("007_rbac")
        if need("008_audit"):
            init_audit_tables(conn)
            mark("008_audit")
        if need("009_projects"):
            init_project_tables(conn)
            mark("009_projects")
        if need("010_schedules"):
            init_sched_tables(conn)
            mark("010_schedules")
        conn.commit()
    return applied
