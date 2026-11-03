"""Feature pages — real logic wired; empty states when no data."""
from __future__ import annotations

from PySide6.QtCore import QObject, QThread, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app.database import list_events, list_scan_runs
from app.modules.dns_intelligence import query_dns
from app.modules.file_analyzer import analyze_file
from app.modules.network_scanner import list_local_interfaces, scan_private_network
from app.modules.osint import ip_lookup
from app.modules.password_auditor import audit_password
from app.modules.port_scanner import scan_ports
from app.modules.report_center import export_html, export_json
from app.modules.system_info import collect_system_info
from app.services.scan_manager import complete_run


class PlaceholderPage(QWidget):
    def __init__(self, title: str, message: str):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.addWidget(QLabel(f"<b>{title}</b>"))
        lab = QLabel(message)
        lab.setObjectName("Subtitle")
        lab.setWordWrap(True)
        lay.addWidget(lab)
        lay.addStretch(1)


class DashboardPage(QWidget):
    def __init__(self):
        super().__init__()
        self.layout = QVBoxLayout(self)
        self.info = QPlainTextEdit()
        self.info.setReadOnly(True)
        self.history = QTableWidget(0, 5)
        self.history.setHorizontalHeaderLabels(["Time", "Module", "Target", "Status", "Summary"])
        self.history.horizontalHeader().setStretchLastSection(True)
        self.events = QTableWidget(0, 4)
        self.events.setHorizontalHeaderLabels(["Time", "Module", "Level", "Message"])
        self.events.horizontalHeader().setStretchLastSection(True)
        self.layout.addWidget(QLabel("System"))
        self.layout.addWidget(self.info)
        self.layout.addWidget(QLabel("Recent scan runs"))
        self.layout.addWidget(self.history)
        self.layout.addWidget(QLabel("Events"))
        self.layout.addWidget(self.events)

    def on_show(self) -> None:
        info = collect_system_info()
        lines = [f"{k}: {v}" for k, v in info.items()]
        self.info.setPlainText("\n".join(lines))
        runs = list_scan_runs(20)
        self.history.setRowCount(0)
        if not runs:
            self.history.setRowCount(1)
            self.history.setItem(0, 0, QTableWidgetItem("No scans yet"))
        else:
            self.history.setRowCount(len(runs))
            for i, r in enumerate(runs):
                for j, key in enumerate(("ts", "module", "target", "status", "summary")):
                    self.history.setItem(i, j, QTableWidgetItem(str(r.get(key) or "")))
        ev = list_events(20)
        self.events.setRowCount(0)
        if not ev:
            self.events.setRowCount(1)
            self.events.setItem(0, 0, QTableWidgetItem("No events yet"))
        else:
            self.events.setRowCount(len(ev))
            for i, e in enumerate(ev):
                for j, key in enumerate(("ts", "module", "level", "message")):
                    self.events.setItem(i, j, QTableWidgetItem(str(e.get(key) or "")))


class FileAnalyzerPage(QWidget):
    def __init__(self):
        super().__init__()
        lay = QVBoxLayout(self)
        row = QHBoxLayout()
        self.path = QLineEdit()
        self.path.setPlaceholderText("Select a file…")
        browse = QPushButton("Browse")
        browse.setObjectName("Primary")
        browse.clicked.connect(self._browse)
        run = QPushButton("Analyze")
        run.setObjectName("Primary")
        run.clicked.connect(self._run)
        row.addWidget(self.path, 1)
        row.addWidget(browse)
        row.addWidget(run)
        lay.addLayout(row)
        self.out = QPlainTextEdit()
        self.out.setReadOnly(True)
        lay.addWidget(self.out)

    def _browse(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select file")
        if path:
            self.path.setText(path)

    def _run(self) -> None:
        path = self.path.text().strip()
        if not path:
            QMessageBox.warning(self, "File Analyzer", "Choose a file first.")
            return
        result = analyze_file(path)
        d = result.to_dict()
        lines = [f"{k}: {v}" for k, v in d.items()]
        self.out.setPlainText("\n".join(lines))
        status = "error" if result.error else "ok"
        summary = result.error or f"sha256={result.sha256[:16]}…"
        complete_run("files", path, status, summary, d)


class PasswordPage(QWidget):
    def __init__(self):
        super().__init__()
        lay = QVBoxLayout(self)
        note = QLabel("Passwords are analyzed locally in memory only. They are not stored or logged.")
        note.setObjectName("Subtitle")
        note.setWordWrap(True)
        lay.addWidget(note)
        self.pw = QLineEdit()
        self.pw.setEchoMode(QLineEdit.EchoMode.Password)
        self.pw.setPlaceholderText("Enter password to audit")
        lay.addWidget(self.pw)
        btn = QPushButton("Audit")
        btn.setObjectName("Primary")
        btn.clicked.connect(self._run)
        lay.addWidget(btn)
        self.out = QPlainTextEdit()
        self.out.setReadOnly(True)
        lay.addWidget(self.out)

    def _run(self) -> None:
        password = self.pw.text()
        if not password:
            QMessageBox.warning(self, "Password Auditor", "Enter a password.")
            return
        report = audit_password(password)
        # clear field so it is not left on screen longer than needed
        self.pw.clear()
        d = report.to_dict()
        lines = [
            f"Length: {d['length']}",
            f"Score: {d['score']}/100 ({d['label']})",
            f"Entropy est.: {d['entropy_bits_est']} bits",
            f"Lower/Upper/Digit/Symbol: {d['has_lower']}/{d['has_upper']}/{d['has_digit']}/{d['has_symbol']}",
            f"Common password list hit: {d['is_common']}",
            "Suggestions:",
        ]
        lines.extend(f"  - {s}" for s in d["suggestions"])
        self.out.setPlainText("\n".join(lines))
        # persist only non-sensitive summary
        complete_run(
            "password",
            None,
            "ok",
            f"score={d['score']} label={d['label']}",
            {"score": d["score"], "label": d["label"], "length": d["length"]},
        )


class DnsPage(QWidget):
    def __init__(self):
        super().__init__()
        lay = QVBoxLayout(self)
        row = QHBoxLayout()
        self.domain = QLineEdit()
        self.domain.setPlaceholderText("example.com")
        btn = QPushButton("Resolve")
        btn.setObjectName("Primary")
        btn.clicked.connect(self._run)
        row.addWidget(self.domain, 1)
        row.addWidget(btn)
        lay.addLayout(row)
        self.out = QPlainTextEdit()
        self.out.setReadOnly(True)
        lay.addWidget(self.out)

    def _run(self) -> None:
        domain = self.domain.text().strip()
        result = query_dns(domain)
        d = result.to_dict()
        lines = [f"Domain: {d['domain']}", f"Resolver: {d['resolver']}", f"OK: {d['ok']}"]
        for rtype, vals in d["records"].items():
            lines.append(f"\n{rtype}:")
            if not vals:
                lines.append("  (empty)")
            for v in vals:
                lines.append(f"  {v}")
        if d["errors"]:
            lines.append("\nErrors:")
            for k, v in d["errors"].items():
                lines.append(f"  {k}: {v}")
        self.out.setPlainText("\n".join(lines))
        complete_run("dns", domain, "ok" if result.ok else "error", f"resolver={result.resolver}", d)


class PortScanPage(QWidget):
    def __init__(self):
        super().__init__()
        lay = QVBoxLayout(self)
        form = QFormLayout()
        self.host = QLineEdit()
        self.host.setPlaceholderText("127.0.0.1")
        self.ports = QLineEdit("22,80,443,3389,8080")
        self.auth = QCheckBox("I confirm I am authorized to scan this target")
        form.addRow("Target host", self.host)
        form.addRow("Ports", self.ports)
        form.addRow("", self.auth)
        lay.addLayout(form)
        btn = QPushButton("Scan ports")
        btn.setObjectName("Primary")
        btn.clicked.connect(self._run)
        lay.addWidget(btn)
        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["Port", "State", "Error"])
        self.table.horizontalHeader().setStretchLastSection(True)
        lay.addWidget(self.table)

    def _run(self) -> None:
        host = self.host.text().strip()
        try:
            ports = [int(x.strip()) for x in self.ports.text().split(",") if x.strip()]
        except ValueError:
            QMessageBox.warning(self, "Port Scanner", "Invalid port list.")
            return
        report = scan_ports(host, ports, authorized=self.auth.isChecked())
        self.table.setRowCount(0)
        if report.error:
            QMessageBox.warning(self, "Port Scanner", report.error)
        self.table.setRowCount(len(report.results))
        for i, r in enumerate(report.results):
            self.table.setItem(i, 0, QTableWidgetItem(str(r.port)))
            self.table.setItem(i, 1, QTableWidgetItem(r.state))
            self.table.setItem(i, 2, QTableWidgetItem(r.error or ""))
        open_n = sum(1 for r in report.results if r.state == "open")
        complete_run(
            "ports",
            host,
            "error" if report.error else "ok",
            report.error or f"open={open_n}/{len(report.results)}",
            report.to_dict(),
        )


class NetworkScanPage(QWidget):
    def __init__(self):
        super().__init__()
        lay = QVBoxLayout(self)
        self.ifaces = QPlainTextEdit()
        self.ifaces.setReadOnly(True)
        self.ifaces.setMaximumHeight(100)
        lay.addWidget(QLabel("Local interfaces"))
        lay.addWidget(self.ifaces)
        form = QFormLayout()
        self.cidr = QLineEdit("127.0.0.0/30")
        self.auth = QCheckBox("I confirm authorization for this private range")
        form.addRow("CIDR", self.cidr)
        form.addRow("", self.auth)
        lay.addLayout(form)
        btn = QPushButton("Reachability scan")
        btn.setObjectName("Primary")
        btn.clicked.connect(self._run)
        lay.addWidget(btn)
        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["IP", "Reachable", "Error"])
        self.table.horizontalHeader().setStretchLastSection(True)
        lay.addWidget(self.table)

    def on_show(self) -> None:
        ifaces = list_local_interfaces()
        if not ifaces:
            self.ifaces.setPlainText("No interfaces discovered.")
        else:
            self.ifaces.setPlainText("\n".join(f"{i.get('hostname')}: {i.get('address')}" for i in ifaces))

    def _run(self) -> None:
        report = scan_private_network(
            self.cidr.text().strip(),
            authorized=self.auth.isChecked(),
            private_only=True,
            max_hosts=64,
        )
        if report.error:
            QMessageBox.warning(self, "Network Scanner", report.error)
        self.table.setRowCount(len(report.hosts))
        for i, h in enumerate(report.hosts):
            self.table.setItem(i, 0, QTableWidgetItem(h.ip))
            self.table.setItem(i, 1, QTableWidgetItem(str(h.reachable)))
            self.table.setItem(i, 2, QTableWidgetItem(h.error or ""))
        up = sum(1 for h in report.hosts if h.reachable)
        complete_run(
            "network",
            report.target,
            "error" if report.error else "ok",
            report.error or f"reachable={up}/{len(report.hosts)}",
            report.to_dict(),
        )



class OsintPage(QWidget):
    def __init__(self):
        super().__init__()
        from app.modules import osint as osint_mod
        self.osint = osint_mod
        lay = QVBoxLayout(self)
        form = QFormLayout()
        self.query = QLineEdit()
        self.query.setPlaceholderText("IP, domain, or username")
        self.mode = QLineEdit("ip")
        self.mode.setPlaceholderText("ip | username | domain | ssl | subs")
        form.addRow("Query", self.query)
        form.addRow("Mode", self.mode)
        lay.addLayout(form)
        btn = QPushButton("Run OSINT")
        btn.setObjectName("Primary")
        btn.clicked.connect(self._run)
        lay.addWidget(btn)
        note = QLabel("Public sources only. Rate limits may apply. No private account access.")
        note.setObjectName("Subtitle")
        lay.addWidget(note)
        self.out = QPlainTextEdit()
        self.out.setReadOnly(True)
        lay.addWidget(self.out)

    def _run(self):
        import json
        q = self.query.text().strip()
        mode = (self.mode.text() or "ip").strip().lower()
        if mode == "ip":
            result = self.osint.ip_lookup(q)
        elif mode == "username":
            result = self.osint.username_search(q)
        elif mode == "domain":
            result = self.osint.full_domain_intel(q)
        elif mode == "ssl":
            result = self.osint.ssl_certificate(q)
        elif mode in ("subs", "subdomains"):
            result = self.osint.passive_subdomains(q)
        else:
            QMessageBox.warning(self, "OSINT", "Mode must be ip, username, domain, ssl, or subs")
            return
        self.out.setPlainText(json.dumps(result, indent=2, default=str)[:50000])
        complete_run("osint", q, "ok" if result.get("ok", True) else "error", mode, result)


class ReportsPage(QWidget):
    def __init__(self):
        super().__init__()
        lay = QVBoxLayout(self)
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["ID", "Time", "Module", "Target", "Status"])
        self.table.horizontalHeader().setStretchLastSection(True)
        lay.addWidget(self.table)
        row = QHBoxLayout()
        j = QPushButton("Export JSON")
        h = QPushButton("Export HTML")
        j.setObjectName("Primary")
        h.setObjectName("Primary")
        j.clicked.connect(lambda: self._export("json"))
        h.clicked.connect(lambda: self._export("html"))
        row.addWidget(j)
        row.addWidget(h)
        lay.addLayout(row)

    def on_show(self) -> None:
        runs = list_scan_runs(50)
        self.table.setRowCount(len(runs))
        if not runs:
            self.table.setRowCount(1)
            self.table.setItem(0, 0, QTableWidgetItem("No stored runs"))
            return
        for i, r in enumerate(runs):
            for j, key in enumerate(("id", "ts", "module", "target", "status")):
                self.table.setItem(i, j, QTableWidgetItem(str(r.get(key) or "")))

    def _export(self, kind: str) -> None:
        if kind == "json":
            path, _ = QFileDialog.getSaveFileName(self, "Export JSON", "bruta_x_report.json", "JSON (*.json)")
            if not path:
                return
            out = export_json(path)
        else:
            path, _ = QFileDialog.getSaveFileName(self, "Export HTML", "bruta_x_report.html", "HTML (*.html)")
            if not path:
                return
            out = export_html(path)
        QMessageBox.information(self, "Reports", f"Wrote {out}")


class VulnPage(QWidget):
    def __init__(self):
        super().__init__()
        from app.modules.vulnerability_scanner import assess_url
        self._assess = assess_url
        lay = QVBoxLayout(self)
        note = QLabel("Non-destructive checks only. Requires authorization confirmation.")
        note.setObjectName("Subtitle")
        note.setWordWrap(True)
        lay.addWidget(note)
        form = QFormLayout()
        self.url = QLineEdit()
        self.url.setPlaceholderText("https://example.com")
        self.auth = QCheckBox("I am authorized to test this target")
        form.addRow("URL", self.url)
        form.addRow("", self.auth)
        lay.addLayout(form)
        btn = QPushButton("Run assessment")
        btn.setObjectName("Primary")
        btn.clicked.connect(self._run)
        lay.addWidget(btn)
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Severity", "Title", "Evidence", "Remediation"])
        self.table.horizontalHeader().setStretchLastSection(True)
        lay.addWidget(self.table)
        self.err = QLabel("")
        self.err.setObjectName("Subtitle")
        lay.addWidget(self.err)

    def _run(self):
        report = self._assess(self.url.text().strip(), authorized=self.auth.isChecked())
        d = report.to_dict()
        if report.errors:
            self.err.setText("; ".join(report.errors))
        else:
            self.err.setText("")
        self.table.setRowCount(len(report.findings))
        for i, f in enumerate(report.findings):
            self.table.setItem(i, 0, QTableWidgetItem(f.severity))
            self.table.setItem(i, 1, QTableWidgetItem(f.title))
            self.table.setItem(i, 2, QTableWidgetItem(f.evidence[:200]))
            self.table.setItem(i, 3, QTableWidgetItem(f.remediation[:200]))
        complete_run(
            "vuln",
            report.target,
            "error" if report.errors and not report.findings else "ok",
            f"findings={len(report.findings)}",
            d,
        )


class NetMonPage(QWidget):
    def __init__(self):
        super().__init__()
        from app.modules.network_monitor import interface_stats, list_connections
        self._list = list_connections
        self._ifaces = interface_stats
        lay = QVBoxLayout(self)
        row = QHBoxLayout()
        btn = QPushButton("Refresh")
        btn.setObjectName("Primary")
        btn.clicked.connect(self.refresh)
        row.addWidget(btn)
        row.addStretch(1)
        lay.addLayout(row)
        self.ifaces = QPlainTextEdit()
        self.ifaces.setReadOnly(True)
        self.ifaces.setMaximumHeight(120)
        lay.addWidget(QLabel("Interfaces"))
        lay.addWidget(self.ifaces)
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Proto", "Local", "Remote", "State", "PID"])
        self.table.horizontalHeader().setStretchLastSection(True)
        lay.addWidget(QLabel("Connections"))
        lay.addWidget(self.table)

    def on_show(self):
        self.refresh()

    def refresh(self):
        stats = self._ifaces()
        self.ifaces.setPlainText(
            "\n".join(
                f"{i.get('iface')}: rx={i.get('rx_bytes')} tx={i.get('tx_bytes')}"
                for i in stats.get("interfaces") or []
            )
            or stats.get("note")
            or str(stats)
        )
        data = self._list()
        rows = data.get("connections") or []
        self.table.setRowCount(len(rows))
        for i, c in enumerate(rows):
            for j, k in enumerate(("proto", "local", "remote", "state", "pid")):
                self.table.setItem(i, j, QTableWidgetItem(str(c.get(k) or "")))


class AIPage(QWidget):
    def __init__(self):
        super().__init__()
        from app.modules.ai_assistant import assist
        self._assist = assist
        lay = QVBoxLayout(self)
        note = QLabel(
            "Offline explanations by default. Remote mode is optional and never sends passwords or file hashes."
        )
        note.setObjectName("Subtitle")
        note.setWordWrap(True)
        lay.addWidget(note)
        form = QFormLayout()
        self.kind = QLineEdit("summary")
        self.kind.setPlaceholderText("vuln | dns | ports | summary")
        self.remote = QCheckBox("Use remote provider (requires BRUTA_AI_KEY)")
        form.addRow("Kind", self.kind)
        form.addRow("", self.remote)
        lay.addLayout(form)
        self.ctx = QPlainTextEdit()
        self.ctx.setPlaceholderText("Optional JSON context from a scan (non-sensitive)")
        lay.addWidget(self.ctx)
        btn = QPushButton("Assist")
        btn.setObjectName("Primary")
        btn.clicked.connect(self._run)
        lay.addWidget(btn)
        self.out = QPlainTextEdit()
        self.out.setReadOnly(True)
        lay.addWidget(self.out)

    def _run(self):
        import json
        raw = self.ctx.toPlainText().strip()
        data = {}
        if raw:
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                QMessageBox.warning(self, "AI Assistant", "Context must be valid JSON or empty.")
                return
        result = self._assist(
            self.kind.text().strip() or "summary",
            data,
            use_remote=self.remote.isChecked(),
        )
        self.out.setPlainText(f"[{result.get('mode')}]\n{result.get('text')}")


class PluginCenterPage(QWidget):
    def __init__(self):
        super().__init__()
        from pathlib import Path as P
        from app.config import DATA_DIR, PACKAGE_ROOT
        from app.plugins.loader import PluginManager
        self.mgr = PluginManager(
            [PACKAGE_ROOT / "plugins"],
            DATA_DIR / "plugins_state.json",
        )
        self.mgr.discover()
        lay = QVBoxLayout(self)
        note = QLabel("Plugins stay disabled until you explicitly enable them.")
        note.setObjectName("Subtitle")
        lay.addWidget(note)
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["ID", "Name", "Version", "Enabled", "Error"])
        self.table.horizontalHeader().setStretchLastSection(True)
        lay.addWidget(self.table)
        row = QHBoxLayout()
        en = QPushButton("Enable selected")
        dis = QPushButton("Disable selected")
        en.setObjectName("Primary")
        en.clicked.connect(lambda: self._set(True))
        dis.clicked.connect(lambda: self._set(False))
        row.addWidget(en)
        row.addWidget(dis)
        lay.addLayout(row)
        self.refresh()

    def refresh(self):
        self.mgr.discover()
        items = self.mgr.list_plugins()
        self.table.setRowCount(len(items))
        for i, p in enumerate(items):
            self.table.setItem(i, 0, QTableWidgetItem(p.get("id", "")))
            self.table.setItem(i, 1, QTableWidgetItem(p.get("name", "")))
            self.table.setItem(i, 2, QTableWidgetItem(p.get("version", "")))
            self.table.setItem(i, 3, QTableWidgetItem(str(p.get("enabled"))))
            self.table.setItem(i, 4, QTableWidgetItem(p.get("error") or ""))

    def on_show(self):
        self.refresh()

    def _set(self, enabled: bool):
        row = self.table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "Plugins", "Select a plugin row")
            return
        pid = self.table.item(row, 0).text()
        try:
            self.mgr.set_enabled(pid, enabled, user_approved=True)
            if enabled:
                self.mgr.load(pid)
            QMessageBox.information(self, "Plugins", f"{pid} enabled={enabled}")
        except Exception as e:
            QMessageBox.warning(self, "Plugins", str(e))
        self.refresh()


class IntelGraphPage(QWidget):
    def __init__(self):
        super().__init__()
        from app.services.correlation import graph_payload, risk_summary
        self._graph = graph_payload
        self._risk = risk_summary
        lay = QVBoxLayout(self)
        self.summary = QLabel()
        self.summary.setObjectName("Subtitle")
        lay.addWidget(self.summary)
        self.out = QPlainTextEdit()
        self.out.setReadOnly(True)
        lay.addWidget(self.out)
        btn = QPushButton("Refresh graph data")
        btn.setObjectName("Primary")
        btn.clicked.connect(self.refresh)
        lay.addWidget(btn)

    def on_show(self):
        self.refresh()

    def refresh(self):
        import json
        risk = self._risk()
        self.summary.setText(
            f"Entities={risk.get('entities')}  Relationships={risk.get('relationships')}  Findings={risk.get('finding_entities')}"
        )
        g = self._graph()
        self.out.setPlainText(json.dumps(g, indent=2)[:100000])


class AutomationPage(QWidget):
    def __init__(self):
        super().__init__()
        from app.services.workflows import example_domain_workflow, run_workflow
        self._example = example_domain_workflow
        self._run = run_workflow
        lay = QVBoxLayout(self)
        form = QFormLayout()
        self.domain = QLineEdit("example.com")
        self.auth = QCheckBox("I authorize this workflow against the target")
        form.addRow("Domain", self.domain)
        form.addRow("", self.auth)
        lay.addLayout(form)
        btn = QPushButton("Run domain workflow")
        btn.setObjectName("Primary")
        btn.clicked.connect(self._go)
        lay.addWidget(btn)
        self.out = QPlainTextEdit()
        self.out.setReadOnly(True)
        lay.addWidget(self.out)

    def _go(self):
        import json
        wf = self._example(self.domain.text().strip())
        result = self._run(wf, authorized=self.auth.isChecked())
        self.out.setPlainText(json.dumps(result, indent=2, default=str)[:100000])


class TaskManagerPage(QWidget):
    def __init__(self):
        super().__init__()
        from app.services.jobs import JobManager
        self.jobs = JobManager(max_workers=2)
        lay = QVBoxLayout(self)
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["ID", "Name", "Status", "Created", "Error"])
        self.table.horizontalHeader().setStretchLastSection(True)
        lay.addWidget(self.table)
        row = QHBoxLayout()
        ref = QPushButton("Refresh")
        ref.setObjectName("Primary")
        ref.clicked.connect(self.refresh)
        row.addWidget(ref)
        lay.addLayout(row)

    def on_show(self):
        self.refresh()

    def refresh(self):
        items = self.jobs.list_jobs()
        self.table.setRowCount(len(items))
        for i, j in enumerate(items):
            self.table.setItem(i, 0, QTableWidgetItem(str(j.get("id"))))
            self.table.setItem(i, 1, QTableWidgetItem(str(j.get("name"))))
            self.table.setItem(i, 2, QTableWidgetItem(str(j.get("status"))))
            self.table.setItem(i, 3, QTableWidgetItem(str(j.get("created_at"))))
            self.table.setItem(i, 4, QTableWidgetItem(str(j.get("error") or "")))


class AnalyticsPage(QWidget):
    def __init__(self):
        super().__init__()
        from app.services.visualization import analytics_summary
        self._sum = analytics_summary
        lay = QVBoxLayout(self)
        self.out = QPlainTextEdit()
        self.out.setReadOnly(True)
        lay.addWidget(self.out)

    def on_show(self):
        import json
        self.out.setPlainText(json.dumps(self._sum(), indent=2, default=str)[:100000])


class AssetsPage(QWidget):
    def __init__(self):
        super().__init__()
        from app.services.assets import add_asset, list_assets
        self._add, self._list = add_asset, list_assets
        lay = QVBoxLayout(self)
        form = QFormLayout()
        self.type = QLineEdit("domain")
        self.value = QLineEdit()
        self.auth = QCheckBox("Mark as authorized for assessment")
        self.scope = QLineEdit()
        self.scope.setPlaceholderText("auth scope note")
        form.addRow("Type", self.type)
        form.addRow("Value", self.value)
        form.addRow("Scope", self.scope)
        form.addRow("", self.auth)
        lay.addLayout(form)
        row = QHBoxLayout()
        addb = QPushButton("Add asset")
        addb.setObjectName("Primary")
        addb.clicked.connect(self._add_row)
        ref = QPushButton("Refresh")
        ref.clicked.connect(self.refresh)
        row.addWidget(addb)
        row.addWidget(ref)
        lay.addLayout(row)
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["ID", "Type", "Value", "Authorized", "Project", "Scope"])
        self.table.horizontalHeader().setStretchLastSection(True)
        lay.addWidget(self.table)

    def on_show(self):
        self.refresh()

    def refresh(self):
        rows = self._list()
        self.table.setRowCount(len(rows))
        for i, a in enumerate(rows):
            for j, k in enumerate(("id", "type", "value", "authorized", "project", "auth_scope")):
                self.table.setItem(i, j, QTableWidgetItem(str(a.get(k) or "")))

    def _add_row(self):
        if not self.value.text().strip():
            QMessageBox.warning(self, "Assets", "Value required")
            return
        self._add(
            self.type.text().strip() or "domain",
            self.value.text().strip(),
            authorized=self.auth.isChecked(),
            auth_scope=self.scope.text().strip(),
        )
        self.refresh()


class ComparePage(QWidget):
    def __init__(self):
        super().__init__()
        from app.services.compare import compare_scans
        self._cmp = compare_scans
        lay = QVBoxLayout(self)
        form = QFormLayout()
        self.a = QLineEdit()
        self.b = QLineEdit()
        form.addRow("Run ID A", self.a)
        form.addRow("Run ID B", self.b)
        lay.addLayout(form)
        btn = QPushButton("Compare")
        btn.setObjectName("Primary")
        btn.clicked.connect(self._go)
        lay.addWidget(btn)
        self.out = QPlainTextEdit()
        self.out.setReadOnly(True)
        lay.addWidget(self.out)

    def _go(self):
        import json
        try:
            ra, rb = int(self.a.text()), int(self.b.text())
        except ValueError:
            QMessageBox.warning(self, "Compare", "Run IDs must be integers")
            return
        self.out.setPlainText(json.dumps(self._cmp(ra, rb), indent=2, default=str)[:100000])


class NotifyPage(QWidget):
    def __init__(self):
        super().__init__()
        from app.services.notifications import list_notifications, mark_read
        self._list, self._read = list_notifications, mark_read
        lay = QVBoxLayout(self)
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["ID", "Time", "Category", "Title", "Read"])
        self.table.horizontalHeader().setStretchLastSection(True)
        lay.addWidget(self.table)
        btn = QPushButton("Mark selected read")
        btn.setObjectName("Primary")
        btn.clicked.connect(self._mark)
        lay.addWidget(btn)

    def on_show(self):
        rows = self._list()
        self.table.setRowCount(len(rows))
        for i, n in enumerate(rows):
            for j, k in enumerate(("id", "ts", "category", "title", "read")):
                self.table.setItem(i, j, QTableWidgetItem(str(n.get(k))))

    def _mark(self):
        r = self.table.currentRow()
        if r < 0:
            return
        self._read(int(self.table.item(r, 0).text()))
        self.on_show()


class SearchPage(QWidget):
    def __init__(self):
        super().__init__()
        from app.services.search import search
        self._search = search
        lay = QVBoxLayout(self)
        row = QHBoxLayout()
        self.q = QLineEdit()
        btn = QPushButton("Search")
        btn.setObjectName("Primary")
        btn.clicked.connect(self._go)
        row.addWidget(self.q, 1)
        row.addWidget(btn)
        lay.addLayout(row)
        self.out = QPlainTextEdit()
        self.out.setReadOnly(True)
        lay.addWidget(self.out)

    def _go(self):
        import json
        self.out.setPlainText(json.dumps(self._search(self.q.text()), indent=2, default=str)[:100000])


class ExportCenterPage(QWidget):
    def __init__(self):
        super().__init__()
        from app.modules.report_center import export_csv, export_html, export_json
        self._json, self._html, self._csv = export_json, export_html, export_csv
        lay = QVBoxLayout(self)
        for label, fn, filt in (
            ("Export JSON", self._json, "JSON (*.json)"),
            ("Export HTML", self._html, "HTML (*.html)"),
            ("Export CSV", self._csv, "CSV (*.csv)"),
        ):
            b = QPushButton(label)
            b.setObjectName("Primary")
            b.clicked.connect(lambda checked=False, f=fn, fl=filt: self._do(f, fl))
            lay.addWidget(b)
        lay.addStretch(1)

    def _do(self, fn, filt):
        path, _ = QFileDialog.getSaveFileName(self, "Export", "bruta_export", filt)
        if not path:
            return
        try:
            out = fn(path)
            QMessageBox.information(self, "Export", f"Wrote {out}")
        except Exception as e:
            QMessageBox.warning(self, "Export", str(e))


class AuditPage(QWidget):
    def __init__(self):
        super().__init__()
        from app.services.audit import list_audit
        self._list = list_audit
        lay = QVBoxLayout(self)
        note = QLabel("Audit trail — secrets are redacted. OWNER/ADMIN access in production policy.")
        note.setObjectName("Subtitle")
        note.setWordWrap(True)
        lay.addWidget(note)
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["ID", "Time", "Actor", "Action", "Resource", "Result"])
        self.table.horizontalHeader().setStretchLastSection(True)
        lay.addWidget(self.table)
        btn = QPushButton("Refresh")
        btn.setObjectName("Primary")
        btn.clicked.connect(self.on_show)
        lay.addWidget(btn)

    def on_show(self):
        rows = self._list(limit=200)
        self.table.setRowCount(len(rows))
        for i, r in enumerate(rows):
            for j, k in enumerate(("id", "ts", "actor", "action", "resource", "result")):
                self.table.setItem(i, j, QTableWidgetItem(str(r.get(k) or "")))


class ProjectsPage(QWidget):
    def __init__(self):
        super().__init__()
        from app.services.projects import create_project, list_projects
        self._create, self._list = create_project, list_projects
        lay = QVBoxLayout(self)
        row = QHBoxLayout()
        self.name = QLineEdit()
        self.name.setPlaceholderText("Project name")
        add = QPushButton("Create")
        add.setObjectName("Primary")
        add.clicked.connect(self._add)
        row.addWidget(self.name, 1)
        row.addWidget(add)
        lay.addLayout(row)
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["ID", "Name", "Description", "Archived"])
        self.table.horizontalHeader().setStretchLastSection(True)
        lay.addWidget(self.table)

    def on_show(self):
        rows = self._list(include_archived=True)
        self.table.setRowCount(len(rows))
        for i, r in enumerate(rows):
            for j, k in enumerate(("id", "name", "description", "archived")):
                self.table.setItem(i, j, QTableWidgetItem(str(r.get(k) or "")))

    def _add(self):
        n = self.name.text().strip()
        if not n:
            QMessageBox.warning(self, "Projects", "Name required")
            return
        self._create(n, actor="owner")
        self.name.clear()
        self.on_show()


class BackupPage(QWidget):
    def __init__(self):
        super().__init__()
        from app.services.backup import create_backup, verify_backup
        self._create, self._verify = create_backup, verify_backup
        lay = QVBoxLayout(self)
        b = QPushButton("Create backup now")
        b.setObjectName("Primary")
        b.clicked.connect(self._run)
        lay.addWidget(b)
        self.out = QPlainTextEdit()
        self.out.setReadOnly(True)
        lay.addWidget(self.out)

    def _run(self):
        import json
        meta = self._create()
        v = self._verify(meta["file"])
        self.out.setPlainText(json.dumps({"backup": meta, "verify": v}, indent=2))


class LicensePage(QWidget):
    def __init__(self):
        super().__init__()
        from app.services.license import license_status
        self._st = license_status
        lay = QVBoxLayout(self)
        self.out = QPlainTextEdit()
        self.out.setReadOnly(True)
        lay.addWidget(self.out)

    def on_show(self):
        import json
        self.out.setPlainText(json.dumps(self._st(), indent=2))


class SettingsPage(QWidget):
    def __init__(self):
        super().__init__()
        from app.ui.themes import list_themes, build_stylesheet
        from app.services.profiles import upsert_profile, get_active, set_active, get_theme
        self._themes = list_themes
        lay = QVBoxLayout(self)
        form = QFormLayout()
        self.theme = QLineEdit(get_theme())
        form.addRow("Theme id", self.theme)
        lay.addLayout(form)
        note = QLabel("Themes: " + ", ".join(list_themes()))
        note.setObjectName("Subtitle")
        note.setWordWrap(True)
        lay.addWidget(note)
        btn = QPushButton("Apply theme to profile")
        btn.setObjectName("Primary")
        btn.clicked.connect(self._apply)
        lay.addWidget(btn)
        lay.addStretch(1)
        self._build = build_stylesheet
        self._upsert = upsert_profile

    def _apply(self):
        tid = self.theme.text().strip()
        if tid not in self._themes():
            QMessageBox.warning(self, "Settings", "Unknown theme id")
            return
        self._upsert("default", {"theme": tid})
        try:
            self.window().setStyleSheet(self._build(tid))
        except Exception:
            pass
        QMessageBox.information(self, "Settings", f"Theme set to {tid}")
