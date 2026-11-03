"""Project workspaces with membership."""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from typing import Any

from app.config import DB_PATH, ensure_dirs
from app.services.rbac import has_permission


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def init_project_tables(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS projects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            description TEXT,
            archived INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS project_members (
            project_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            role TEXT NOT NULL,
            PRIMARY KEY (project_id, username)
        );
        CREATE TABLE IF NOT EXISTS project_assets (
            project_id INTEGER NOT NULL,
            asset_id INTEGER NOT NULL,
            PRIMARY KEY (project_id, asset_id)
        );
        """
    )


def create_project(name: str, description: str = "", actor: str = "system") -> int:
    ensure_dirs()
    with sqlite3.connect(str(DB_PATH)) as conn:
        init_project_tables(conn)
        cur = conn.execute(
            "INSERT INTO projects (name, description, created_at) VALUES (?,?,?)",
            (name.strip(), description, _utc()),
        )
        pid = int(cur.lastrowid)
        conn.execute(
            "INSERT OR IGNORE INTO project_members (project_id, username, role) VALUES (?,?,?)",
            (pid, actor, "ADMINISTRATOR"),
        )
        conn.commit()
        return pid


def list_projects(include_archived: bool = False) -> list[dict[str, Any]]:
    with sqlite3.connect(str(DB_PATH)) as conn:
        conn.row_factory = sqlite3.Row
        init_project_tables(conn)
        if include_archived:
            rows = conn.execute("SELECT * FROM projects ORDER BY id DESC").fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM projects WHERE archived=0 ORDER BY id DESC"
            ).fetchall()
        return [dict(r) for r in rows]


def user_can_access_project(username: str, role: str, project_id: int) -> bool:
    if has_permission(role, "admin.full") or has_permission(role, "projects.manage"):
        return True
    with sqlite3.connect(str(DB_PATH)) as conn:
        init_project_tables(conn)
        row = conn.execute(
            "SELECT 1 FROM project_members WHERE project_id=? AND username=?",
            (project_id, username),
        ).fetchone()
    return row is not None


def assign_member(project_id: int, username: str, member_role: str = "ANALYST") -> None:
    with sqlite3.connect(str(DB_PATH)) as conn:
        init_project_tables(conn)
        conn.execute(
            "INSERT OR REPLACE INTO project_members (project_id, username, role) VALUES (?,?,?)",
            (project_id, username, member_role),
        )
        conn.commit()


def archive_project(project_id: int) -> None:
    with sqlite3.connect(str(DB_PATH)) as conn:
        init_project_tables(conn)
        conn.execute("UPDATE projects SET archived=1 WHERE id=?", (project_id,))
        conn.commit()
