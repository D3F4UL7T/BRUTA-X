"""OSINT intelligence — username, domain/RDAP, IP geo, SSL cert, passive subdomains."""
from __future__ import annotations

import concurrent.futures
import json
import re
import socket
import ssl
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from app.services.authorization import is_valid_domain, parse_ip

UA = "BRUTA-X/1.1 (+osint; BRUTA Technologies)"

USERNAME_SITES = {
    "GitHub": "https://github.com/{u}",
    "GitLab": "https://gitlab.com/{u}",
    "Reddit": "https://www.reddit.com/user/{u}",
    "HackerNews": "https://news.ycombinator.com/user?id={u}",
    "Keybase": "https://keybase.io/{u}",
    "DockerHub": "https://hub.docker.com/u/{u}",
    "npm": "https://www.npmjs.com/~{u}",
    "PyPI": "https://pypi.org/user/{u}",
    "Dev.to": "https://dev.to/{u}",
    "Twitch": "https://www.twitch.tv/{u}",
}


def _http_json(url: str, timeout: float = 12.0) -> tuple[int, Any]:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        try:
            return e.code, json.loads(body)
        except Exception:
            return e.code, body[:300]
    except Exception as e:
        return 0, str(e)


def _http_status(url: str, timeout: float = 8.0) -> int | str:
    req = urllib.request.Request(url, headers={"User-Agent": UA}, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception as e:
        return f"err:{type(e).__name__}"


def ip_lookup(ip: str, timeout: float = 10.0) -> dict[str, Any]:
    ip = ip.strip()
    if not parse_ip(ip):
        return {"ok": False, "error": "Invalid IP address"}
    code, data = _http_json(f"https://ipapi.co/{ip}/json/", timeout=timeout)
    if code == 200 and isinstance(data, dict) and not data.get("error"):
        return {
            "ok": True,
            "source": "ipapi.co",
            "ip": data.get("ip"),
            "city": data.get("city"),
            "region": data.get("region"),
            "country": data.get("country_name"),
            "country_code": data.get("country_code"),
            "org": data.get("org"),
            "asn": data.get("asn"),
            "latitude": data.get("latitude"),
            "longitude": data.get("longitude"),
            "timezone": data.get("timezone"),
            "raw": data,
        }
    return {"ok": False, "source": "ipapi.co", "status": code, "error": data}


def username_search(username: str, timeout: float = 8.0, workers: int = 10) -> dict[str, Any]:
    u = username.strip().lstrip("@")
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,39}", u):
        return {"ok": False, "error": "Invalid username format"}
    found, misses = [], []

    def probe(site: str, url: str):
        st = _http_status(url, timeout=timeout)
        return site, url, st

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futs = [pool.submit(probe, s, t.format(u=u)) for s, t in USERNAME_SITES.items()]
        for fut in concurrent.futures.as_completed(futs):
            site, url, st = fut.result()
            if st == 200:
                found.append({"site": site, "url": url, "status": st})
            else:
                misses.append({"site": site, "url": url, "status": st})
    return {
        "ok": True,
        "username": u,
        "checked": len(USERNAME_SITES),
        "present": found,
        "absent_or_blocked": misses,
    }


def domain_rdap(domain: str, timeout: float = 15.0) -> dict[str, Any]:
    domain = domain.strip().rstrip(".").lower()
    if not is_valid_domain(domain):
        return {"ok": False, "error": "Invalid domain"}
    code, data = _http_json(f"https://rdap.org/domain/{domain}", timeout=timeout)
    if code != 200 or not isinstance(data, dict):
        return {"ok": False, "status": code, "error": data}
    events = {e.get("eventAction"): e.get("eventDate") for e in (data.get("events") or [])}
    nservers = [ns.get("ldhName") for ns in (data.get("nameservers") or []) if ns.get("ldhName")]
    return {
        "ok": True,
        "domain": data.get("ldhName") or domain,
        "handle": data.get("handle"),
        "status": data.get("status"),
        "events": events,
        "nameservers": nservers,
        "raw": data,
    }


def ssl_certificate(host: str, port: int = 443, timeout: float = 8.0) -> dict[str, Any]:
    host = host.strip().rstrip(".")
    if not host:
        return {"ok": False, "error": "Empty host"}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        if not cert:
            return {"ok": False, "error": "Empty certificate"}
        subject = dict(x[0] for x in cert.get("subject", ()))
        issuer = dict(x[0] for x in cert.get("issuer", ()))
        san = []
        for typ, val in cert.get("subjectAltName", ()) or []:
            san.append(f"{typ}:{val}")
        return {
            "ok": True,
            "host": host,
            "port": port,
            "subject_cn": subject.get("commonName"),
            "issuer_cn": issuer.get("commonName"),
            "issuer_org": issuer.get("organizationName"),
            "not_before": cert.get("notBefore"),
            "not_after": cert.get("notAfter"),
            "serial": cert.get("serialNumber"),
            "san": san,
            "version": cert.get("version"),
        }
    except ssl.SSLCertVerificationError as e:
        return {"ok": False, "error": f"cert verify failed: {e}", "host": host}
    except Exception as e:
        return {"ok": False, "error": str(e), "host": host}


def passive_subdomains(domain: str, timeout: float = 15.0) -> dict[str, Any]:
    """Passive discovery via Certificate Transparency (crt.sh)."""
    domain = domain.strip().rstrip(".").lower()
    if not is_valid_domain(domain):
        return {"ok": False, "error": "Invalid domain"}
    q = urllib.request.quote(f"%.{domain}")
    url = f"https://crt.sh/?q={q}&output=json"
    code, data = _http_json(url, timeout=timeout)
    if code != 200:
        return {"ok": False, "status": code, "error": data, "source": "crt.sh"}
    names: set[str] = set()
    if isinstance(data, list):
        for row in data:
            nv = row.get("name_value") or ""
            for part in re.split(r"[\n,]", nv):
                n = part.strip().lower().lstrip("*.")
                if n.endswith(domain) and is_valid_domain(n):
                    names.add(n)
    return {
        "ok": True,
        "domain": domain,
        "source": "crt.sh",
        "count": len(names),
        "subdomains": sorted(names),
    }


def full_domain_intel(domain: str) -> dict[str, Any]:
    from app.modules.dns_intelligence import query_dns

    domain = domain.strip().rstrip(".")
    return {
        "domain": domain,
        "dns": query_dns(domain).to_dict(),
        "rdap": domain_rdap(domain),
        "ssl": ssl_certificate(domain),
        "subdomains": passive_subdomains(domain),
        "collected_at": datetime.now(timezone.utc).isoformat(),
    }
