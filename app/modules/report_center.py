"""Report generation from stored scan runs — JSON and HTML only from real data."""
from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app import __version__
from app.database import get_scan_run, list_scan_runs


def build_report_payload(run_id: int | None = None) -> dict[str, Any]:
    if run_id is not None:
        run = get_scan_run(run_id)
        runs = [run] if run else []
    else:
        runs = []
        for summary in list_scan_runs(limit=20):
            full = get_scan_run(summary["id"])
            if full:
                runs.append(full)
    return {
        "generator": "BRUTA X",
        "version": __version__,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "run_count": len(runs),
        "runs": runs,
    }


def export_json(path: str, run_id: int | None = None) -> str:
    payload = build_report_payload(run_id)
    p = Path(path)
    p.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    return str(p.resolve())


def export_html(path: str, run_id: int | None = None) -> str:
    payload = build_report_payload(run_id)
    rows = []
    for run in payload["runs"]:
        if not run:
            continue
        rows.append(
            "<tr>"
            f"<td>{html.escape(str(run.get('id')))}</td>"
            f"<td>{html.escape(str(run.get('ts')))}</td>"
            f"<td>{html.escape(str(run.get('module')))}</td>"
            f"<td>{html.escape(str(run.get('target') or ''))}</td>"
            f"<td>{html.escape(str(run.get('status')))}</td>"
            f"<td>{html.escape(str(run.get('summary') or ''))}</td>"
            "</tr>"
        )
    body = "\n".join(rows) or "<tr><td colspan='6'>No stored runs</td></tr>"
    doc = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>BRUTA X Report</title>
<style>
body{{font-family:Segoe UI,Arial,sans-serif;background:#1a1b1e;color:#e8e8e8;padding:24px}}
table{{border-collapse:collapse;width:100%}}
th,td{{border:1px solid #333;padding:8px;text-align:left}}
th{{background:#2b2d31}}
h1{{color:#39FF14}}
</style></head><body>
<h1>BRUTA X Report</h1>
<p>Version {html.escape(payload['version'])} · Generated {html.escape(payload['generated_at'])}</p>
<table>
<thead><tr><th>ID</th><th>Time</th><th>Module</th><th>Target</th><th>Status</th><th>Summary</th></tr></thead>
<tbody>
{body}
</tbody></table>
</body></html>
"""
    p = Path(path)
    p.write_text(doc, encoding="utf-8")
    return str(p.resolve())
