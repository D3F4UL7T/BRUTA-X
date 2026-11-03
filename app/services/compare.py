"""Scan comparison — evidence-based deltas only."""
from __future__ import annotations

import json
from typing import Any

from app.database import get_scan_run


def _findings_set(result: dict[str, Any]) -> dict[str, dict[str, Any]]:
    out = {}
    for f in result.get("findings") or []:
        if not isinstance(f, dict):
            continue
        key = f.get("id") or f.get("title") or json.dumps(f, sort_keys=True)[:120]
        out[str(key)] = f
    return out


def _dns_map(result: dict[str, Any]) -> dict[str, set[str]]:
    recs = result.get("records") or {}
    return {k: set(v or []) for k, v in recs.items()}


def compare_scans(run_a: int, run_b: int) -> dict[str, Any]:
    a = get_scan_run(run_a)
    b = get_scan_run(run_b)
    if not a or not b:
        return {"ok": False, "error": "One or both runs not found"}
    if a.get("module") != b.get("module"):
        return {
            "ok": False,
            "error": f"Incompatible modules: {a.get('module')} vs {b.get('module')}",
        }
    try:
        ra = json.loads(a.get("result_json") or "{}")
        rb = json.loads(b.get("result_json") or "{}")
    except json.JSONDecodeError:
        return {"ok": False, "error": "Corrupt result_json"}

    report: dict[str, Any] = {
        "ok": True,
        "run_a": run_a,
        "run_b": run_b,
        "module": a.get("module"),
        "new": [],
        "resolved": [],
        "changed": [],
        "notes": [],
    }

    if a.get("module") == "vuln":
        fa, fb = _findings_set(ra), _findings_set(rb)
        for k in fb.keys() - fa.keys():
            report["new"].append({"id": k, "finding": fb[k], "evidence": "present in B not A"})
        for k in fa.keys() - fb.keys():
            report["resolved"].append({"id": k, "finding": fa[k], "evidence": "present in A not B"})
        for k in fa.keys() & fb.keys():
            if fa[k].get("severity") != fb[k].get("severity"):
                report["changed"].append(
                    {
                        "id": k,
                        "from": fa[k].get("severity"),
                        "to": fb[k].get("severity"),
                        "evidence": "severity field differs",
                    }
                )
    elif a.get("module") == "dns":
        da, db = _dns_map(ra), _dns_map(rb)
        for rtype in set(da) | set(db):
            added = db.get(rtype, set()) - da.get(rtype, set())
            removed = da.get(rtype, set()) - db.get(rtype, set())
            for v in added:
                report["new"].append({"rr": rtype, "value": v, "evidence": f"DNS {rtype} added"})
            for v in removed:
                report["resolved"].append(
                    {"rr": rtype, "value": v, "evidence": f"DNS {rtype} removed (or missing in B)"}
                )
        report["notes"].append("DNS absence in B may be NXDOMAIN/timeout, not definitive removal.")
    else:
        report["notes"].append(
            f"Generic compare for module={a.get('module')}: structural key diff only."
        )
        ka, kb = set(ra.keys()), set(rb.keys())
        report["new"] = [{"key": k, "evidence": "key only in B"} for k in sorted(kb - ka)]
        report["resolved"] = [{"key": k, "evidence": "key only in A"} for k in sorted(ka - kb)]
    return report
