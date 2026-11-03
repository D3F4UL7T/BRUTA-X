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


def export_pdf(path: str, run_id: int | None = None) -> str:
    """PDF export if reportlab is installed; otherwise raises with clear message."""
    payload = build_report_payload(run_id)
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas
    except ImportError as e:
        raise RuntimeError(
            "PDF export requires reportlab. Install: pip install reportlab"
        ) from e
    from pathlib import Path as P
    c = canvas.Canvas(path, pagesize=letter)
    width, height = letter
    y = height - 48
    c.setFont("Helvetica-Bold", 16)
    c.drawString(48, y, "BRUTA X Security Report")
    y -= 24
    c.setFont("Helvetica", 10)
    c.drawString(48, y, f"Version {payload.get('version')}  |  {payload.get('generated_at')}")
    y -= 28
    for run in payload.get("runs") or []:
        if y < 72:
            c.showPage()
            y = height - 48
        line = f"#{run.get('id')} {run.get('ts')} {run.get('module')} {run.get('target')} [{run.get('status')}]"
        c.drawString(48, y, line[:110])
        y -= 14
        summary = str(run.get("summary") or "")[:110]
        c.drawString(60, y, summary)
        y -= 18
    c.save()
    return str(P(path).resolve())


def export_csv(path: str, run_id: int | None = None) -> str:
    import csv
    from pathlib import Path as P
    payload = build_report_payload(run_id)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["id", "ts", "module", "target", "status", "summary"])
        for run in payload.get("runs") or []:
            if not run:
                continue
            w.writerow([run.get("id"), run.get("ts"), run.get("module"), run.get("target"), run.get("status"), run.get("summary")])
    return str(P(path).resolve())
