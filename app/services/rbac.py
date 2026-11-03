"""Deny-by-default role-based access control (local accounts)."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
from datetime import datetime, timezone
from typing import Any

from app.config import DB_PATH, DATA_DIR, ensure_dirs

ROLES = ("OWNER", "ADMINISTRATOR", "ANALYST", "VIEWER")

# permission -> minimum roles that grant it
PERMISSIONS: dict[str, frozenset[str]] = {
    "admin.full": frozenset({"OWNER"}),
    "users.manage": frozenset({"OWNER", "ADMINISTRATOR"}),
    "projects.manage": frozenset({"OWNER", "ADMINISTRATOR"}),
    "plugins.manage": frozenset({"OWNER", "ADMINISTRATOR"}),
    "assets.manage": frozenset({"OWNER", "ADMINISTRATOR", "ANALYST"}),
    "assets.view": frozenset({"OWNER", "ADMINISTRATOR", "ANALYST", "VIEWER"}),
    "scans.run": frozenset({"OWNER", "ADMINISTRATOR", "ANALYST"}),
    "scans.view": frozenset({"OWNER", "ADMINISTRATOR", "ANALYST", "VIEWER"}),
    "workflows.run": frozenset({"OWNER", "ADMINISTRATOR", "ANALYST"}),
    "reports.generate": frozenset({"OWNER", "ADMINISTRATOR", "ANALYST"}),
    "reports.view": frozenset({"OWNER", "ADMINISTRATOR", "ANALYST", "VIEWER"}),
    "audit.view": frozenset({"OWNER", "ADMINISTRATOR"}),
    "api.manage": frozenset({"OWNER", "ADMINISTRATOR"}),
    "backup.manage": frozenset({"OWNER", "ADMINISTRATOR"}),
    "settings.manage": frozenset({"OWNER"}),
    "license.view": frozenset({"OWNER", "ADMINISTRATOR", "ANALYST", "VIEWER"}),
}


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def init_rbac_tables(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            role TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token_hash TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        );
        """
    )


def _hash_password(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 120_000).hex()


def ensure_default_owner(password: str | None = None) -> None:
    """Create local owner if no users exist. Password from env BRUTA_OWNER_PASSWORD or generated once."""
    ensure_dirs()
    with sqlite3.connect(str(DB_PATH)) as conn:
        init_rbac_tables(conn)
        n = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if n:
            return
        pw = password or os.environ.get("BRUTA_OWNER_PASSWORD") or secrets.token_urlsafe(12)
        salt = secrets.token_hex(16)
        conn.execute(
            "INSERT INTO users (username, role, password_hash, salt, active, created_at) VALUES (?,?,?,?,1,?)",
            ("owner", "OWNER", _hash_password(pw, salt), salt, _utc()),
        )
        conn.commit()
        # store bootstrap password only in local file once (not in repo)
        bootstrap = DATA_DIR / "owner_bootstrap.txt"
        if not bootstrap.exists():
            bootstrap.write_text(
                f"username=owner\npassword={pw}\nChange this password after first login.\n",
                encoding="utf-8",
            )


def authenticate(username: str, password: str) -> dict[str, Any] | None:
    with sqlite3.connect(str(DB_PATH)) as conn:
        conn.row_factory = sqlite3.Row
        init_rbac_tables(conn)
        row = conn.execute(
            "SELECT * FROM users WHERE username=? AND active=1", (username,)
        ).fetchone()
    if not row:
        return None
    if not hmac.compare_digest(row["password_hash"], _hash_password(password, row["salt"])):
        return None
    return {"id": row["id"], "username": row["username"], "role": row["role"]}


def create_session(user_id: int, hours: int = 12) -> str:
    token = secrets.token_urlsafe(32)
    th = hashlib.sha256(token.encode()).hexdigest()
    from datetime import timedelta

    exp = (datetime.now(timezone.utc) + timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S UTC")
    with sqlite3.connect(str(DB_PATH)) as conn:
        init_rbac_tables(conn)
        conn.execute(
            "INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?,?,?,?)",
            (th, user_id, _utc(), exp),
        )
        conn.commit()
    return token


def user_from_token(token: str) -> dict[str, Any] | None:
    th = hashlib.sha256(token.encode()).hexdigest()
    with sqlite3.connect(str(DB_PATH)) as conn:
        conn.row_factory = sqlite3.Row
        init_rbac_tables(conn)
        row = conn.execute(
            "SELECT u.id, u.username, u.role, s.expires_at FROM sessions s "
            "JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND u.active=1",
            (th,),
        ).fetchone()
    if not row:
        return None
    # simple string compare for expiry is OK given UTC format sortable
    if row["expires_at"] < _utc():
        return None
    return {"id": row["id"], "username": row["username"], "role": row["role"]}


def has_permission(role: str, permission: str) -> bool:
    allowed = PERMISSIONS.get(permission)
    if not allowed:
        return False
    return role in allowed


def require(role: str, permission: str) -> None:
    if not has_permission(role, permission):
        raise PermissionError(f"denied: {permission}")


def set_user_role(actor_role: str, username: str, new_role: str) -> None:
    require(actor_role, "users.manage")
    if new_role not in ROLES:
        raise ValueError("invalid role")
    if new_role == "OWNER" and actor_role != "OWNER":
        raise PermissionError("only OWNER may assign OWNER")
    with sqlite3.connect(str(DB_PATH)) as conn:
        init_rbac_tables(conn)
        conn.execute("UPDATE users SET role=? WHERE username=?", (new_role, username))
        conn.commit()
