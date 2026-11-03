"""Coordinates scan persistence."""
from __future__ import annotations

from typing import Any

from app.database import log_event, save_scan_run


def complete_run(
    module: str,
    target: str | None,
    status: str,
    summary: str,
    result: Any,
) -> int:
    run_id = save_scan_run(module, target, status, summary, result)
    log_event(module, f"run #{run_id} {status}: {summary}")
    return run_id
