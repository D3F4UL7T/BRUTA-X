"""SQLite backup and restore with safety checks."""
from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.config import DB_PATH, DATA_DIR, ensure_dirs


def _utc_slug() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def create_backup(dest_dir: str | Path | None = None) -> dict[str, Any]:
    ensure_dirs()
    dest_dir = Path(dest_dir or (DATA_DIR / "backups"))
    dest_dir.mkdir(parents=True, exist_ok=True)
    name = f"bruta_x_{_utc_slug()}.db"
    dest = dest_dir / name
    # online backup API
    src = sqlite3.connect(str(DB_PATH))
    dst = sqlite3.connect(str(dest))
    try:
        src.backup(dst)
    finally:
        dst.close()
        src.close()
    h = hashlib.sha256(dest.read_bytes()).hexdigest()
    meta = {"file": str(dest), "sha256": h, "created": _utc_slug(), "source": str(DB_PATH)}
    (dest.with_suffix(".json")).write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return meta


def verify_backup(path: str | Path) -> dict[str, Any]:
    path = Path(path)
    if not path.exists():
        return {"ok": False, "error": "missing"}
    h = hashlib.sha256(path.read_bytes()).hexdigest()
    meta_path = path.with_suffix(".json")
    if meta_path.exists():
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        match = meta.get("sha256") == h
        return {"ok": match, "sha256": h, "meta_match": match}
    return {"ok": True, "sha256": h, "meta_match": None}


def restore_backup(path: str | Path, *, confirm: bool = False) -> dict[str, Any]:
    if not confirm:
        return {"ok": False, "error": "confirm=True required"}
    path = Path(path)
    v = verify_backup(path)
    if not v.get("ok"):
        return {"ok": False, "error": "verification failed", "verify": v}
    ensure_dirs()
    # recovery point
    recovery = create_backup(DATA_DIR / "backups" / "pre_restore")
    shutil.copy2(path, DB_PATH)
    return {"ok": True, "restored_from": str(path), "recovery_point": recovery}
