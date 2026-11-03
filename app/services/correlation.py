"""Intelligence correlation engine — evidence-backed relationships only."""
from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

from app.config import DB_PATH, ensure_dirs

IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


@dataclass
class Entity:
    id: str  # type:value
    type: str
    value: str
    first_seen: str
    last_seen: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Relationship:
    source: str
    target: str
    rel_type: str
    evidence: str
    module: str
    confidence: float
    ts: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def init_intel_tables(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS intel_entities (
            id TEXT PRIMARY KEY,
            type TEXT NOT NULL,
            value TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS intel_relationships (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT NOT NULL,
            target TEXT NOT NULL,
            rel_type TEXT NOT NULL,
            evidence TEXT NOT NULL,
            module TEXT NOT NULL,
            confidence REAL NOT NULL,
            ts TEXT NOT NULL,
            UNIQUE(source, target, rel_type, evidence)
        );
        """
    )


def entity_id(etype: str, value: str) -> str:
    return f"{etype}:{value.strip().lower()}"


def upsert_entity(etype: str, value: str) -> str:
    ensure_dirs()
    eid = entity_id(etype, value)
    now = _utc()
    with sqlite3.connect(str(DB_PATH)) as conn:
        init_intel_tables(conn)
        row = conn.execute("SELECT id FROM intel_entities WHERE id=?", (eid,)).fetchone()
        if row:
            conn.execute("UPDATE intel_entities SET last_seen=? WHERE id=?", (now, eid))
        else:
            conn.execute(
                "INSERT INTO intel_entities (id, type, value, first_seen, last_seen) VALUES (?,?,?,?,?)",
                (eid, etype, value.strip(), now, now),
            )
        conn.commit()
    return eid


def add_relationship(
    source: str,
    target: str,
    rel_type: str,
    evidence: str,
    module: str,
    confidence: float,
) -> None:
    confidence = max(0.0, min(1.0, float(confidence)))
    with sqlite3.connect(str(DB_PATH)) as conn:
        init_intel_tables(conn)
        conn.execute(
            "INSERT OR IGNORE INTO intel_relationships "
            "(source, target, rel_type, evidence, module, confidence, ts) "
            "VALUES (?,?,?,?,?,?,?)",
            (source, target, rel_type, evidence[:2000], module, confidence, _utc()),
        )
        conn.commit()


def ingest_scan_result(module: str, target: str | None, result: Any) -> dict[str, Any]:
    """Derive entities/relationships only when evidence exists in result."""
    created_rel = 0
    created_ent = 0
    if not isinstance(result, dict):
        try:
            result = json.loads(result) if isinstance(result, str) else {}
        except Exception:
            return {"entities": 0, "relationships": 0}

    def ent(t: str, v: str) -> str:
        nonlocal created_ent
        created_ent += 1
        return upsert_entity(t, v)

    def rel(a: str, b: str, rtype: str, evidence: str, conf: float) -> None:
        nonlocal created_rel
        add_relationship(a, b, rtype, evidence, module, conf)
        created_rel += 1

    if module in ("dns",) or result.get("records"):
        domain = result.get("domain") or target
        if domain:
            d = ent("domain", domain)
            for ip in (result.get("records") or {}).get("A") or []:
                if IP_RE.match(ip):
                    i = ent("ip", ip)
                    rel(d, i, "resolves_to", f"DNS A {domain}->{ip}", 0.9)
            for ip in (result.get("records") or {}).get("AAAA") or []:
                i = ent("ip", ip)
                rel(d, i, "resolves_to", f"DNS AAAA {domain}->{ip}", 0.9)

    if result.get("subdomains") or (result.get("subdomains") == [] and "count" in result):
        domain = result.get("domain") or target
        if domain:
            d = ent("domain", domain)
            for sub in result.get("subdomains") or []:
                s = ent("domain", sub)
                rel(d, s, "has_subdomain", f"CT/passive {sub}", 0.7)

    if module == "osint" and result.get("ok") and result.get("asn"):
        ip = result.get("ip") or target
        if ip and IP_RE.match(str(ip)):
            i = ent("ip", str(ip))
            asn = str(result.get("asn"))
            a = ent("asn", asn)
            rel(i, a, "announced_by", f"geo/asn source {result.get('source')}", 0.8)

    if result.get("subject_cn") or result.get("not_after"):
        host = result.get("host") or target
        if host:
            h = ent("domain", host)
            cn = result.get("subject_cn") or "cert"
            c = ent("certificate", f"{host}:{cn}")
            rel(h, c, "has_certificate", f"TLS CN={cn}", 0.85)

    if module == "vuln" and result.get("findings"):
        turl = result.get("target") or target or ""
        host = re.sub(r"^https?://", "", turl).split("/")[0]
        if host:
            h = ent("domain", host.split(":")[0])
            for f in result.get("findings") or []:
                if not isinstance(f, dict):
                    continue
                fid = f.get("id") or f.get("title") or "finding"
                fe = ent("finding", f"{host}:{fid}")
                rel(
                    h,
                    fe,
                    "has_finding",
                    f"{f.get('severity')}: {f.get('evidence','')[:200]}",
                    0.75 if f.get("severity") != "info" else 0.5,
                )

    return {"entities": created_ent, "relationships": created_rel}


def graph_payload(limit: int = 300) -> dict[str, Any]:
    with sqlite3.connect(str(DB_PATH)) as conn:
        conn.row_factory = sqlite3.Row
        init_intel_tables(conn)
        ents = [dict(r) for r in conn.execute("SELECT * FROM intel_entities LIMIT ?", (limit,))]
        rels = [
            dict(r)
            for r in conn.execute(
                "SELECT source, target, rel_type, evidence, module, confidence, ts "
                "FROM intel_relationships ORDER BY id DESC LIMIT ?",
                (limit,),
            )
        ]
    return {
        "nodes": [{"id": e["id"], "type": e["type"], "label": e["value"]} for e in ents],
        "edges": [
            {
                "source": r["source"],
                "target": r["target"],
                "type": r["rel_type"],
                "evidence": r["evidence"],
                "module": r["module"],
                "confidence": r["confidence"],
                "ts": r["ts"],
            }
            for r in rels
        ],
    }


def risk_summary() -> dict[str, Any]:
    with sqlite3.connect(str(DB_PATH)) as conn:
        init_intel_tables(conn)
        n_ent = conn.execute("SELECT COUNT(*) FROM intel_entities").fetchone()[0]
        n_rel = conn.execute("SELECT COUNT(*) FROM intel_relationships").fetchone()[0]
        findings = conn.execute(
            "SELECT COUNT(*) FROM intel_entities WHERE type='finding'"
        ).fetchone()[0]
    return {
        "entities": n_ent,
        "relationships": n_rel,
        "finding_entities": findings,
        "note": "Counts reflect ingested evidence only; absence of edges is not a clean bill of health.",
    }
