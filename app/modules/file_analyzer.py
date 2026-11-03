"""File analyzer — hashes and metadata. Never executes files."""
from __future__ import annotations

import hashlib
import os
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path


CHUNK = 1024 * 1024  # 1 MiB


@dataclass
class FileAnalysis:
    path: str
    exists: bool
    size: int | None = None
    extension: str | None = None
    modified: str | None = None
    created: str | None = None
    sha256: str | None = None
    sha512: str | None = None
    error: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def analyze_file(path: str) -> FileAnalysis:
    p = Path(path).expanduser()
    if not p.exists():
        return FileAnalysis(path=str(p), exists=False, error="File not found")
    if not p.is_file():
        return FileAnalysis(path=str(p), exists=True, error="Not a regular file")
    try:
        st = p.stat()
        h256 = hashlib.sha256()
        h512 = hashlib.sha512()
        with p.open("rb") as f:
            while True:
                block = f.read(CHUNK)
                if not block:
                    break
                h256.update(block)
                h512.update(block)
        return FileAnalysis(
            path=str(p.resolve()),
            exists=True,
            size=st.st_size,
            extension=p.suffix.lower() or None,
            modified=datetime.fromtimestamp(st.st_mtime).isoformat(timespec="seconds"),
            created=datetime.fromtimestamp(st.st_ctime).isoformat(timespec="seconds"),
            sha256=h256.hexdigest(),
            sha512=h512.hexdigest(),
        )
    except PermissionError:
        return FileAnalysis(path=str(p), exists=True, error="Permission denied")
    except OSError as e:
        return FileAnalysis(path=str(p), exists=True, error=str(e))
