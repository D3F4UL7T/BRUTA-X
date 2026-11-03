"""Local interface discovery and limited private-network reachability checks."""
from __future__ import annotations

import concurrent.futures
import socket
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from typing import Any

from app.services.authorization import (
    network_is_allowed,
    parse_ip,
    parse_network,
)


@dataclass
class HostResult:
    ip: str
    reachable: bool
    error: str | None = None


@dataclass
class NetworkScanReport:
    target: str
    authorized: bool
    interfaces: list[dict[str, str]] = field(default_factory=list)
    hosts: list[HostResult] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "authorized": self.authorized,
            "error": self.error,
            "interfaces": self.interfaces,
            "hosts": [asdict(h) for h in self.hosts],
        }


def list_local_interfaces() -> list[dict[str, str]]:
    """Best-effort local address discovery without external deps."""
    found: list[dict[str, str]] = []
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None):
            ip = info[4][0]
            if ip and not ip.startswith("127."):
                found.append({"hostname": hostname, "address": ip})
    except OSError:
        pass
    # also try UDP connect trick for default egress IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        if not any(x["address"] == ip for x in found):
            found.append({"hostname": "default-egress", "address": ip})
    except OSError:
        pass
    return found


def _ping_host(ip: str, timeout_sec: float = 1.0) -> HostResult:
    """ICMP ping via system ping. May require permissions; failures reported honestly."""
    try:
        if sys.platform.startswith("win"):
            cmd = ["ping", "-n", "1", "-w", str(int(timeout_sec * 1000)), ip]
        else:
            cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout_sec))), ip]
        r = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_sec + 2,
        )
        ok = r.returncode == 0
        return HostResult(ip=ip, reachable=ok, error=None if ok else "no reply")
    except Exception as e:
        return HostResult(ip=ip, reachable=False, error=str(e))


def scan_private_network(
    cidr: str,
    *,
    authorized: bool,
    private_only: bool = True,
    max_hosts: int = 256,
    timeout: float = 1.0,
    max_workers: int = 32,
) -> NetworkScanReport:
    if not authorized:
        return NetworkScanReport(
            target=cidr,
            authorized=False,
            error="Authorization not confirmed.",
            interfaces=list_local_interfaces(),
        )
    net = parse_network(cidr)
    if net is None:
        return NetworkScanReport(
            target=cidr,
            authorized=True,
            error="Invalid CIDR",
            interfaces=list_local_interfaces(),
        )
    if not network_is_allowed(net, private_only=private_only):
        return NetworkScanReport(
            target=cidr,
            authorized=True,
            error="Target is not a private/loopback network. Public ranges blocked by policy.",
            interfaces=list_local_interfaces(),
        )
    hosts = list(net.hosts())
    if net.num_addresses <= 2:
        hosts = [net.network_address]
    if len(hosts) > max_hosts:
        return NetworkScanReport(
            target=cidr,
            authorized=True,
            error=f"Host count {len(hosts)} exceeds limit {max_hosts}",
            interfaces=list_local_interfaces(),
        )
    results: list[HostResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futs = [pool.submit(_ping_host, str(h), timeout) for h in hosts]
        for fut in concurrent.futures.as_completed(futs):
            results.append(fut.result())
    results.sort(key=lambda h: tuple(int(x) for x in h.ip.split(".") if x.isdigit()))
    return NetworkScanReport(
        target=cidr,
        authorized=True,
        interfaces=list_local_interfaces(),
        hosts=results,
    )
