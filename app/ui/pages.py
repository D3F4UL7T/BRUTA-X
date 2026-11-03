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
        lay = QVBoxLayout(self)
        row = QHBoxLayout()
        self.ip = QLineEdit()
        self.ip.setPlaceholderText("1.1.1.1")
        btn = QPushButton("IP lookup")
        btn.setObjectName("Primary")
        btn.clicked.connect(self._run)
        row.addWidget(self.ip, 1)
        row.addWidget(btn)
        lay.addLayout(row)
        note = QLabel("Uses public ipapi.co when network is available. No fabricated data.")
        note.setObjectName("Subtitle")
        lay.addWidget(note)
        self.out = QPlainTextEdit()
        self.out.setReadOnly(True)
        lay.addWidget(self.out)

    def _run(self) -> None:
        ip = self.ip.text().strip()
        result = ip_lookup(ip)
        self.out.setPlainText(
            "\n".join(f"{k}: {v}" for k, v in (result.get('data') or result).items())
            if result.get("ok")
            else f"Error: {result.get('error')}"
        )
        complete_run("osint", ip, "ok" if result.get("ok") else "error", str(result.get("error") or "ip lookup"), result)


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
