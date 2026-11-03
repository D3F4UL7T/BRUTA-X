"""Phase 2 unit tests — real logic, no fabricated findings."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.modules.osint import username_search, ssl_certificate, domain_rdap, passive_subdomains, ip_lookup
from app.modules.vulnerability_scanner import assess_url
from app.modules.network_monitor import list_connections, interface_stats
from app.modules.ai_assistant import assist, sanitize_context, offline_explain
from app.modules.password_auditor import audit_password


class TestOsintPhase2(unittest.TestCase):
    def test_username_invalid(self):
        r = username_search("")
        self.assertFalse(r.get("ok"))

    def test_ip_invalid(self):
        r = ip_lookup("not-an-ip")
        self.assertFalse(r.get("ok"))

    def test_ssl_empty(self):
        r = ssl_certificate("")
        self.assertFalse(r.get("ok"))

    def test_rdap_invalid(self):
        r = domain_rdap("-bad-")
        self.assertFalse(r.get("ok"))


class TestVuln(unittest.TestCase):
    def test_auth_required(self):
        r = assess_url("https://example.com", authorized=False)
        self.assertFalse(r.authorized)
        self.assertTrue(r.errors)

    def test_example_com(self):
        r = assess_url("https://example.com", authorized=True, timeout=15)
        self.assertTrue(r.authorized)
        # may have findings or network errors — should not crash
        d = r.to_dict()
        self.assertIn("findings", d)
        self.assertIn("severity_counts", d)


class TestNetMon(unittest.TestCase):
    def test_connections(self):
        data = list_connections(limit=20)
        self.assertIn("connections", data)

    def test_ifaces(self):
        data = interface_stats()
        self.assertIn("ok", data)


class TestAI(unittest.TestCase):
    def test_sanitize(self):
        s = sanitize_context({"password": "secret", "port": 22})
        self.assertEqual(s["password"], "[redacted]")
        self.assertEqual(s["port"], 22)

    def test_offline_vuln(self):
        text = offline_explain(
            "vuln",
            {"findings": [{"severity": "low", "title": "t", "remediation": "r"}]},
        )
        self.assertIn("finding", text.lower())

    def test_assist_offline(self):
        r = assist("summary", {}, use_remote=False)
        self.assertTrue(r["ok"])
        self.assertEqual(r["mode"], "offline")

    def test_password_not_in_ai_context_expectation(self):
        # passwords never go through assist in app; sanitize still redacts
        s = sanitize_context({"password": audit_password("x").to_dict()})
        self.assertEqual(s["password"], "[redacted]")


if __name__ == "__main__":
    unittest.main()
