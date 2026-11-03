"""Visualization data builders — real stored data only."""
from __future__ import annotations

from typing import Any

from app.database import list_scan_runs
from app.modules.network_scanner import list_local_interfaces
from app.services.correlation import graph_payload, risk_summary


def topology_from_last_network_scan() -> dict[str, Any]:
    """Build a simple topology graph from the latest network scan run if present."""
    nodes = []
    edges = []
    for iface in list_local_interfaces():
        nodes.append(
            {
                "id": f"iface:{iface.get('address')}",
                "label": iface.get("address"),
                "type": "interface",
                "meta": iface,
            }
        )
    for run in list_scan_runs(50):
        if run.get("module") != "network":
            continue
        from app.database import get_scan_run
        import json

        full = get_scan_run(run["id"])
        if not full:
            continue
        try:
            data = json.loads(full.get("result_json") or "{}")
        except Exception:
            continue
        for h in data.get("hosts") or []:
            ip = h.get("ip")
            if not ip:
                continue
            nodes.append(
                {
                    "id": f"host:{ip}",
                    "label": ip,
                    "type": "host",
                    "reachable": h.get("reachable"),
                }
            )
            # link to first interface if any
            if nodes and nodes[0]["type"] == "interface":
                edges.append(
                    {
                        "source": nodes[0]["id"],
                        "target": f"host:{ip}",
                        "type": "on_segment",
                        "evidence": f"network scan run #{run['id']}",
                    }
                )
        break
    return {"nodes": nodes, "edges": edges, "source": "scan_history+interfaces"}


def analytics_summary() -> dict[str, Any]:
    runs = list_scan_runs(100)
    by_module: dict[str, int] = {}
    by_status: dict[str, int] = {}
    for r in runs:
        by_module[r["module"]] = by_module.get(r["module"], 0) + 1
        by_status[r["status"]] = by_status.get(r["status"], 0) + 1
    return {
        "scan_runs": len(runs),
        "by_module": by_module,
        "by_status": by_status,
        "intel": risk_summary(),
        "osint_graph": graph_payload(limit=100),
    }
