"""Lightweight OSINT helpers — IP geo via public HTTP APIs when network allows."""
from __future__ import annotations

import json
import urllib.request
from typing import Any


UA = "BRUTA-X/1.0 (+research; BRUTA Technologies)"


def ip_lookup(ip: str, timeout: float = 10.0) -> dict[str, Any]:
    ip = ip.strip()
    url = f"https://ipapi.co/{ip}/json/"
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
        return {"ok": True, "source": "ipapi.co", "data": data}
    except Exception as e:
        return {"ok": False, "source": "ipapi.co", "error": str(e)}
