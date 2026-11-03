"""Webhook delivery with SSRF protections."""
from __future__ import annotations

import ipaddress
import json
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlparse

BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]


def is_safe_webhook_url(url: str) -> tuple[bool, str]:
    try:
        p = urlparse(url)
    except Exception:
        return False, "invalid url"
    if p.scheme not in ("https",):
        return False, "only https allowed"
    host = p.hostname or ""
    if host in ("localhost", "metadata.google.internal"):
        return False, "blocked host"
    try:
        # resolve? keep simple: reject IP literals in blocked ranges
        ip = ipaddress.ip_address(host)
        for net in BLOCKED_NETWORKS:
            if ip in net:
                return False, "blocked private/metadata range"
    except ValueError:
        # hostname — still block obvious metadata names
        if host.endswith(".internal") or host.startswith("169.254."):
            return False, "blocked host pattern"
    return True, "ok"


def deliver_webhook(url: str, event: str, payload: dict[str, Any], timeout: float = 8.0) -> dict[str, Any]:
    ok, reason = is_safe_webhook_url(url)
    if not ok:
        return {"ok": False, "error": reason}
    # strip sensitive keys
    safe = {k: v for k, v in payload.items() if k.lower() not in {"password", "token", "api_key", "secret"}}
    body = json.dumps({"event": event, "data": safe}).encode()
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "BRUTA-X-Webhook/1.5"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return {"ok": True, "status": resp.status}
    except Exception as e:
        return {"ok": False, "error": str(e)}
