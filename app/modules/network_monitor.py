"""Live local network monitor — connections and interface stats (read-only)."""
from __future__ import annotations

import os
import socket
import subprocess
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass
class ConnectionRow:
    proto: str
    local: str
    remote: str
    state: str
    pid: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _parse_ss(output: str) -> list[ConnectionRow]:
    rows: list[ConnectionRow] = []
    for line in output.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 5:
            continue
        proto = parts[0]
        state = parts[1]
        local = parts[4] if len(parts) > 4 else ""
        remote = parts[5] if len(parts) > 5 else ""
        pid = None
        for p in parts:
            if p.startswith("pid="):
                pid = p.split("=", 1)[1].split(",")[0]
        rows.append(ConnectionRow(proto=proto, local=local, remote=remote, state=state, pid=pid))
    return rows


def _parse_netstat(output: str) -> list[ConnectionRow]:
    rows: list[ConnectionRow] = []
    for line in output.splitlines():
        if not line.startswith(("TCP", "UDP", "tcp", "udp")):
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        proto = parts[0]
        local = parts[1]
        remote = parts[2]
        state = parts[3] if len(parts) > 3 else ""
        pid = parts[-1] if len(parts) > 4 else None
        rows.append(ConnectionRow(proto=proto, local=local, remote=remote, state=state, pid=pid))
    return rows


def list_connections(limit: int = 200) -> dict[str, Any]:
    """Best-effort connection inventory using ss or netstat."""
    errors: list[str] = []
    rows: list[ConnectionRow] = []
    try:
        if sys.platform.startswith("win"):
            r = subprocess.run(
                ["netstat", "-ano"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if r.returncode == 0:
                rows = _parse_netstat(r.stdout)
            else:
                errors.append(r.stderr.strip() or "netstat failed")
        else:
            r = subprocess.run(
                ["ss", "-tunap"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if r.returncode == 0:
                rows = _parse_ss(r.stdout)
            else:
                r2 = subprocess.run(
                    ["netstat", "-tunap"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if r2.returncode == 0:
                    rows = _parse_netstat(r2.stdout)
                else:
                    errors.append("ss/netstat unavailable or permission denied")
    except FileNotFoundError:
        errors.append("ss/netstat not found on PATH")
    except Exception as e:
        errors.append(str(e))
    return {
        "ok": not errors or bool(rows),
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "count": len(rows[:limit]),
        "connections": [c.to_dict() for c in rows[:limit]],
        "errors": errors,
    }


def interface_stats() -> dict[str, Any]:
    """Linux /proc/net/dev stats when available; otherwise hostname-only."""
    path = "/proc/net/dev"
    if os.path.exists(path):
        stats = []
        try:
            with open(path, encoding="utf-8") as _f:
                lines = _f.read().splitlines()[2:]
            for line in lines:
                if ":" not in line:
                    continue
                name, rest = line.split(":", 1)
                fields = rest.split()
                if len(fields) >= 9:
                    stats.append(
                        {
                            "iface": name.strip(),
                            "rx_bytes": int(fields[0]),
                            "rx_packets": int(fields[1]),
                            "tx_bytes": int(fields[8]),
                            "tx_packets": int(fields[9]) if len(fields) > 9 else 0,
                        }
                    )
            return {"ok": True, "interfaces": stats, "source": "/proc/net/dev"}
        except Exception as e:
            return {"ok": False, "error": str(e)}
    return {
        "ok": True,
        "interfaces": [],
        "source": "unavailable",
        "hostname": socket.gethostname(),
        "note": "Detailed iface counters require Linux /proc or platform APIs",
    }
