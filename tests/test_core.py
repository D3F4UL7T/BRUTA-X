"""Unit tests for core BRUTA X logic (no GUI required)."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.modules.file_analyzer import analyze_file
from app.modules.password_auditor import audit_password
from app.modules.dns_intelligence import query_dns
from app.modules.port_scanner import scan_ports
from app.modules.network_scanner import list_local_interfaces, scan_private_network
from app.services.authorization import is_valid_domain, network_is_allowed, parse_network
from app.database import init_db, save_scan_run, list_scan_runs
from app.modules.report_center import export_json, build_report_payload
from app.config import DB_PATH


class TestPassword(unittest.TestCase):
    def test_weak(self):
        r = audit_password("123456")
        self.assertLess(r.score, 40)
        self.assertTrue(r.is_common)

    def test_stronger(self):
        r = audit_password("Correct-Horse-Battery-Staple-92!")
        self.assertGreaterEqual(r.score, 50)
        self.assertFalse(r.is_common)


class TestFile(unittest.TestCase):
    def test_hash(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"bruta-x-test")
            path = f.name
        r = analyze_file(path)
        self.assertTrue(r.exists)
        self.assertEqual(r.size, 12)
        self.assertEqual(len(r.sha256 or ""), 64)
        self.assertEqual(len(r.sha512 or ""), 128)
        self.assertIsNone(r.error)

    def test_missing(self):
        r = analyze_file("/nonexistent/bruta_x_file")
        self.assertFalse(r.exists)
        self.assertIsNotNone(r.error)


class TestDns(unittest.TestCase):
    def test_invalid(self):
        r = query_dns("-bad-")
        self.assertFalse(r.ok)
        self.assertIn("input", r.errors)

    def test_localhost_or_example(self):
        r = query_dns("localhost")
        # may or may not resolve depending on environment; should not crash
        self.assertEqual(r.domain, "localhost")


class TestPorts(unittest.TestCase):
    def test_requires_auth(self):
        r = scan_ports("127.0.0.1", [1], authorized=False)
        self.assertFalse(r.authorized)
        self.assertIsNotNone(r.error)

    def test_local_closed_or_open(self):
        r = scan_ports("127.0.0.1", [1], authorized=True, timeout=0.5, max_workers=2)
        self.assertTrue(r.authorized)
        self.assertEqual(len(r.results), 1)
        self.assertIn(r.results[0].state, {"open", "closed", "filtered/unknown"})


class TestNetwork(unittest.TestCase):
    def test_public_blocked(self):
        r = scan_private_network("8.8.8.0/30", authorized=True, private_only=True)
        self.assertIsNotNone(r.error)
        self.assertIn("private", r.error.lower())

    def test_interfaces(self):
        ifaces = list_local_interfaces()
        self.assertIsInstance(ifaces, list)


class TestAuth(unittest.TestCase):
    def test_domain(self):
        self.assertTrue(is_valid_domain("example.com"))
        self.assertFalse(is_valid_domain(""))

    def test_net(self):
        n = parse_network("10.0.0.0/24")
        self.assertIsNotNone(n)
        self.assertTrue(network_is_allowed(n, private_only=True))


class TestDbReport(unittest.TestCase):
    def test_roundtrip(self):
        init_db()
        rid = save_scan_run("test", "t", "ok", "summary", {"a": 1})
        runs = list_scan_runs(5)
        self.assertTrue(any(r["id"] == rid for r in runs))
        payload = build_report_payload(rid)
        self.assertEqual(payload["run_count"], 1)
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "r.json"
            export_json(str(path), rid)
            self.assertTrue(path.exists())


if __name__ == "__main__":
    unittest.main()
