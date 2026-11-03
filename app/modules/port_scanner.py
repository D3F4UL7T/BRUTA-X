"""Conservative TCP connect port scanner. Requires explicit target authorization."""
from __future__ import annotations

import concurrent.futures
import socket
from dataclasses import asdict, dataclass, field
from typing import Any

from app.services.authorization import parse_ip, validate_port


@dataclass
class PortResult:
    port: int
    state: str  # open | closed | filtered/unknown
    error: str | None = None


@dataclass
class PortScanReport:
    target: str
    authorized: bool
    results: list[PortResult] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "authorized": self.authorized,
            "error": self.error,
            "results": [asdict(r) for r in self.results],
        }


def _check_port(host: str, port: int, timeout: float) -> PortResult:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return PortResult(port=port, state="open")
    except socket.timeout:
        return PortResult(port=port, state="filtered/unknown", error="timeout")
    except ConnectionRefusedError:
        return PortResult(port=port, state="closed")
    except OSError as e:
        return PortResult(port=port, state="filtered/unknown", error=str(e))


def scan_ports(
    host: str,
    ports: list[int],
    *,
    authorized: bool,
    timeout: float = 1.5,
    max_workers: int = 64,
) -> PortScanReport:
    host = host.strip()
    if not authorized:
        return PortScanReport(
            target=host,
            authorized=False,
            error="Authorization not confirmed. Active port checks are blocked.",
        )
    ip = parse_ip(host)
    if ip is None and not host:
        return PortScanReport(target=host, authorized=True, error="Invalid host")
    # allow hostname or IP; user confirmed authorization
    clean_ports = sorted({p for p in ports if validate_port(p)})
    if not clean_ports:
        return PortScanReport(target=host, authorized=True, error="No valid ports")
    if len(clean_ports) > 1024:
        return PortScanReport(
            target=host,
            authorized=True,
            error="Too many ports (max 1024 per run)",
        )

    results: list[PortResult] = []
    workers = max(1, min(max_workers, len(clean_ports)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(_check_port, host, p, timeout): p for p in clean_ports}
        for fut in concurrent.futures.as_completed(futs):
            results.append(fut.result())
    results.sort(key=lambda r: r.port)
    return PortScanReport(target=host, authorized=True, results=results)
