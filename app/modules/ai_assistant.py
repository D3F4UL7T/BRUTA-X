"""AI security assistant — offline rule-based + optional HTTP API provider.

Never transmits passwords, tokens, or local file contents.
"""
from __future__ import annotations

import json
import os
import urllib.request
from typing import Any


SENSITIVE_KEYS = {
    "password", "passwd", "secret", "token", "api_key", "apikey", "authorization",
    "cookie", "private_key", "sha256", "sha512",
}


def sanitize_context(obj: Any) -> Any:
    """Strip sensitive fields before any external send."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if str(k).lower() in SENSITIVE_KEYS:
                out[k] = "[redacted]"
            else:
                out[k] = sanitize_context(v)
        return out
    if isinstance(obj, list):
        return [sanitize_context(x) for x in obj[:50]]
    if isinstance(obj, str) and len(obj) > 2000:
        return obj[:2000] + "…"
    return obj


def offline_explain(kind: str, data: dict[str, Any]) -> str:
    """Deterministic local explanations — no network, no fabrication of findings."""
    data = sanitize_context(data)
    if kind == "vuln":
        findings = data.get("findings") or []
        if not findings:
            return (
                "No findings were present in the provided scan result. "
                "That means the checker did not record issues — not that the target is proven secure."
            )
        lines = [
            f"This report contains {len(findings)} evidence-based finding(s).",
            "Prioritize by severity: critical/high first, then medium/low.",
            "",
        ]
        for f in findings[:15]:
            lines.append(
                f"- [{f.get('severity','?').upper()}] {f.get('title')}: {f.get('remediation')}"
            )
        lines.append("")
        lines.append("Remediate systematically and re-scan after changes. Avoid treating info-level items as incidents.")
        return "\n".join(lines)
    if kind == "dns":
        recs = data.get("records") or {}
        errs = data.get("errors") or {}
        lines = [f"DNS resolver used: {data.get('resolver')}", f"Domain: {data.get('domain')}"]
        if errs:
            lines.append("Errors: " + ", ".join(f"{k}={v}" for k, v in errs.items()))
        for rtype, vals in recs.items():
            lines.append(f"{rtype}: {', '.join(vals) if vals else '(none)'}")
        lines.append("Validate NS/MX at your registrar if records are missing unexpectedly.")
        return "\n".join(lines)
    if kind == "ports":
        results = data.get("results") or []
        open_ports = [r for r in results if r.get("state") == "open"]
        lines = [
            f"Target: {data.get('target')}",
            f"Open ports: {', '.join(str(r.get('port')) for r in open_ports) or 'none observed'}",
            "Only scan systems you are authorized to test. Restrict exposure of admin ports.",
        ]
        return "\n".join(lines)
    if kind == "summary":
        return (
            "Offline assistant summary mode.\n"
            "Paste structured scan JSON from BRUTA X modules. "
            "External AI is optional and never receives passwords or hashes."
        )
    return (
        "Offline mode active. Select a scan result type (vuln/dns/ports) "
        "or configure an API provider for generative summaries of non-sensitive data."
    )


def remote_complete(
    prompt: str,
    *,
    api_url: str,
    api_key: str,
    model: str = "gpt-4o-mini",
    timeout: float = 30.0,
) -> dict[str, Any]:
    """Generic OpenAI-compatible chat completions. Key never logged."""
    if not api_url or not api_key:
        return {"ok": False, "error": "API URL and key required for remote mode"}
    payload = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a defensive security assistant for BRUTA X. "
                    "Only discuss provided findings. Do not invent vulnerabilities. "
                    "Refuse requests involving exploitation or credential abuse."
                ),
            },
            {"role": "user", "content": prompt[:12000]},
        ],
        "temperature": 0.2,
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        api_url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
            "User-Agent": "BRUTA-X/1.1",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read().decode("utf-8", errors="replace"))
        text = (
            body.get("choices", [{}])[0]
            .get("message", {})
            .get("content")
        )
        if not text:
            return {"ok": False, "error": "Empty model response", "raw": body}
        return {"ok": True, "text": text, "provider": "openai-compatible"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def assist(
    kind: str,
    data: dict[str, Any] | None = None,
    question: str | None = None,
    *,
    use_remote: bool = False,
    api_url: str | None = None,
    api_key: str | None = None,
) -> dict[str, Any]:
    data = sanitize_context(data or {})
    offline = offline_explain(kind, data)
    if not use_remote:
        return {"ok": True, "mode": "offline", "text": offline}
    prompt = (
        f"Kind: {kind}\nQuestion: {question or 'Explain findings and remediations.'}\n"
        f"Data JSON:\n{json.dumps(data)[:8000]}\n\n"
        f"Local baseline notes:\n{offline}"
    )
    remote = remote_complete(
        prompt,
        api_url=api_url or os.environ.get("BRUTA_AI_URL", "https://api.openai.com/v1/chat/completions"),
        api_key=api_key or os.environ.get("BRUTA_AI_KEY", ""),
    )
    if remote.get("ok"):
        return {"ok": True, "mode": "remote", "text": remote["text"]}
    return {
        "ok": True,
        "mode": "offline_fallback",
        "text": offline + f"\n\n[Remote provider failed: {remote.get('error')}]",
    }
