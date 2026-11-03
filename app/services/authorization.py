"""Authorization helpers — restrict active probing to private ranges by default."""
from __future__ import annotations

import ipaddress
import re


DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


def is_valid_domain(name: str) -> bool:
    name = name.strip().rstrip(".")
    if not name or len(name) > 253:
        return False
    return bool(DOMAIN_RE.match(name))


def parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError:
        return None


def is_private_ip(ip: ipaddress._BaseAddress) -> bool:
    return bool(getattr(ip, "is_private", False) or getattr(ip, "is_loopback", False))


def parse_network(cidr: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    try:
        return ipaddress.ip_network(cidr.strip(), strict=False)
    except ValueError:
        return None


def network_is_allowed(net: ipaddress._BaseNetwork, private_only: bool = True) -> bool:
    if not private_only:
        return True
    # allow private + loopback only
    return bool(net.is_private or str(net).startswith("127."))


def validate_port(port: int) -> bool:
    return 1 <= port <= 65535
