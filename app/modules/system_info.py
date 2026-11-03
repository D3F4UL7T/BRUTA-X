"""Real local system information for dashboard."""
from __future__ import annotations

import platform
import socket
from datetime import datetime
from typing import Any


def collect_system_info() -> dict[str, Any]:
    info: dict[str, Any] = {
        "hostname": socket.gethostname(),
        "fqdn": socket.getfqdn(),
        "platform": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "processor": platform.processor() or "n/a",
        "python": platform.python_version(),
        "collected_at": datetime.now().isoformat(timespec="seconds"),
    }
    try:
        info["cpu_count"] = __import__("os").cpu_count()
    except Exception:
        info["cpu_count"] = None
    return info
