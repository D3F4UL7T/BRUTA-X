"""DNS intelligence — real lookups via dnspython or stdlib fallback."""
from __future__ import annotations

import socket
from dataclasses import asdict, dataclass, field
from typing import Any

from app.services.authorization import is_valid_domain

RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA")


@dataclass
class DnsResult:
    domain: str
    resolver: str
    records: dict[str, list[str]] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)
    ok: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _lookup_dnspython(domain: str, timeout: float) -> DnsResult:
    import dns.resolver  # type: ignore

    res = dns.resolver.Resolver()
    res.lifetime = timeout
    out = DnsResult(domain=domain, resolver="dnspython")
    for rtype in RECORD_TYPES:
        try:
            ans = res.resolve(domain, rtype)
            out.records[rtype] = sorted({r.to_text() for r in ans})
        except dns.resolver.NXDOMAIN:
            out.errors[rtype] = "NXDOMAIN"
            out.ok = False
            break
        except dns.resolver.NoAnswer:
            out.records[rtype] = []
        except dns.exception.Timeout:
            out.errors[rtype] = "timeout"
        except Exception as e:
            out.errors[rtype] = str(e)
    return out


def _lookup_stdlib(domain: str) -> DnsResult:
    out = DnsResult(domain=domain, resolver="stdlib")
    try:
        infos = socket.getaddrinfo(domain, None)
        a, aaaa = set(), set()
        for info in infos:
            ip = info[4][0]
            if ":" in ip:
                aaaa.add(ip)
            else:
                a.add(ip)
        out.records["A"] = sorted(a)
        out.records["AAAA"] = sorted(aaaa)
    except socket.gaierror as e:
        out.ok = False
        out.errors["A"] = str(e)
    return out


def query_dns(domain: str, timeout: float = 8.0) -> DnsResult:
    domain = domain.strip().rstrip(".")
    if not is_valid_domain(domain):
        return DnsResult(
            domain=domain,
            resolver="none",
            ok=False,
            errors={"input": "Invalid domain name"},
        )
    try:
        import dns.resolver  # noqa: F401

        return _lookup_dnspython(domain, timeout)
    except ImportError:
        return _lookup_stdlib(domain)
