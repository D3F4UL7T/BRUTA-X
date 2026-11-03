"""Edition / license management — offline config, no fake remote servers."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.config import DATA_DIR, ensure_dirs

EDITIONS = {
    "community": {
        "name": "BRUTA X Community",
        "features": ["core", "osint_basic", "reports_basic", "plugins_community"],
    },
    "professional": {
        "name": "BRUTA X Professional",
        "features": [
            "core",
            "osint_basic",
            "reports_advanced",
            "analytics",
            "workflows",
            "assets_advanced",
        ],
    },
    "enterprise": {
        "name": "BRUTA X Enterprise",
        "features": [
            "core",
            "osint_basic",
            "reports_advanced",
            "analytics",
            "workflows",
            "assets_advanced",
            "rbac",
            "audit",
            "api",
            "webhooks",
            "collaboration",
        ],
    },
}

LICENSE_PATH = DATA_DIR / "license.json"


def get_license() -> dict[str, Any]:
    ensure_dirs()
    if not LICENSE_PATH.exists():
        data = {"edition": "enterprise", "status": "dev-unrestricted", "signed": False}
        LICENSE_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return data
    return json.loads(LICENSE_PATH.read_text(encoding="utf-8"))


def set_edition(edition: str) -> dict[str, Any]:
    if edition not in EDITIONS:
        raise ValueError("unknown edition")
    data = get_license()
    data["edition"] = edition
    data["status"] = "configured"
    LICENSE_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return data


def feature_allowed(feature: str) -> bool:
    lic = get_license()
    # development unrestricted unless explicitly community/professional locked
    if lic.get("status") == "dev-unrestricted":
        return True
    edition = lic.get("edition", "community")
    feats = EDITIONS.get(edition, EDITIONS["community"])["features"]
    return feature in feats


def license_status() -> dict[str, Any]:
    lic = get_license()
    edition = lic.get("edition", "community")
    return {
        "edition": edition,
        "name": EDITIONS[edition]["name"],
        "features": EDITIONS[edition]["features"],
        "status": lic.get("status"),
        "signed": bool(lic.get("signed")),
        "note": "Offline edition config only. Signed license verification requires customer public keys — not hardcoded here.",
    }
