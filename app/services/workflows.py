"""Workflow automation — sequential authorized module steps."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable

from app.modules.dns_intelligence import query_dns
from app.modules.osint import full_domain_intel, ssl_certificate
from app.modules.report_center import export_json
from app.modules.vulnerability_scanner import assess_url
from app.services.correlation import ingest_scan_result
from app.services.scan_manager import complete_run


@dataclass
class WorkflowStep:
    action: str
    params: dict[str, Any] = field(default_factory=dict)


@dataclass
class Workflow:
    id: str
    name: str
    steps: list[WorkflowStep]
    require_authorization: bool = True


# Safe built-in actions only
ACTIONS: dict[str, Callable[..., Any]] = {}


def _register(name: str):
    def deco(fn):
        ACTIONS[name] = fn
        return fn

    return deco


@_register("dns.lookup")
def act_dns(domain: str, **_):
    r = query_dns(domain)
    d = r.to_dict()
    complete_run("dns", domain, "ok" if r.ok else "error", "workflow", d)
    ingest_scan_result("dns", domain, d)
    return d


@_register("osint.domain")
def act_domain(domain: str, **_):
    d = full_domain_intel(domain)
    complete_run("osint", domain, "ok", "workflow-domain", d)
    ingest_scan_result("osint", domain, d.get("dns") or {})
    if d.get("subdomains"):
        ingest_scan_result("osint", domain, d["subdomains"])
    if d.get("ssl"):
        ingest_scan_result("osint", domain, d["ssl"])
    return d


@_register("ssl.inspect")
def act_ssl(host: str, **_):
    d = ssl_certificate(host)
    complete_run("osint", host, "ok" if d.get("ok") else "error", "workflow-ssl", d)
    ingest_scan_result("osint", host, d)
    return d


@_register("vuln.assess")
def act_vuln(url: str, authorized: bool = False, **_):
    r = assess_url(url, authorized=authorized)
    d = r.to_dict()
    complete_run("vuln", url, "ok" if not r.errors else "error", "workflow-vuln", d)
    ingest_scan_result("vuln", url, d)
    return d


@_register("report.json")
def act_report(path: str = "workflow_report.json", **_):
    return {"path": export_json(path)}


def run_workflow(
    workflow: Workflow,
    *,
    authorized: bool = False,
    cancel_event=None,
) -> dict[str, Any]:
    if workflow.require_authorization and not authorized:
        return {"ok": False, "error": "Workflow requires explicit authorization"}
    results = []
    for i, step in enumerate(workflow.steps):
        if cancel_event is not None and cancel_event.is_set():
            return {"ok": False, "cancelled": True, "completed_steps": results}
        fn = ACTIONS.get(step.action)
        if not fn:
            results.append({"step": i, "action": step.action, "error": "unknown action"})
            return {"ok": False, "error": f"unknown action {step.action}", "steps": results}
        params = dict(step.params)
        # force authorized flag into vuln steps from workflow-level consent
        if step.action == "vuln.assess":
            params["authorized"] = authorized
        try:
            out = fn(**params)
            results.append({"step": i, "action": step.action, "ok": True, "result": out})
        except TypeError:
            # functions may not accept cancel_event
            out = fn(**{k: v for k, v in params.items()})
            results.append({"step": i, "action": step.action, "ok": True, "result": out})
        except Exception as e:
            results.append({"step": i, "action": step.action, "ok": False, "error": str(e)})
            return {"ok": False, "error": str(e), "steps": results}
    return {"ok": True, "steps": results}


def example_domain_workflow(domain: str) -> Workflow:
    return Workflow(
        id="domain_basic",
        name="Domain basic assessment",
        require_authorization=True,
        steps=[
            WorkflowStep("dns.lookup", {"domain": domain}),
            WorkflowStep("ssl.inspect", {"host": domain}),
            WorkflowStep("vuln.assess", {"url": f"https://{domain}"}),
            WorkflowStep("osint.domain", {"domain": domain}),
            WorkflowStep("report.json", {"path": f"report_{domain.replace('.', '_')}.json"}),
        ],
    )
