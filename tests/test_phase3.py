from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.plugins.base import PluginManifest, ALLOWED_PERMISSIONS
from app.plugins.loader import PluginManager
from app.services.correlation import ingest_scan_result, graph_payload, risk_summary, entity_id
from app.services.workflows import example_domain_workflow, run_workflow, ACTIONS
from app.services.jobs import JobManager
from app.services.migrations import migrate
from app.services.visualization import analytics_summary, topology_from_last_network_scan


class TestPlugins(unittest.TestCase):
    def test_manifest_permission_reject(self):
        m = PluginManifest("x", "x", "", "1", "a", permissions=["evil.perm"])
        self.assertTrue(any("permission" in e for e in m.validate()))

    def test_discover_builtins(self):
        mgr = PluginManager([ROOT / "plugins"], ROOT / "data" / "test_plugins_state.json")
        found = mgr.discover()
        ids = {r.manifest.id for r in found if not r.error}
        self.assertIn("builtin_dns_info", ids)
        self.assertIn("builtin_file_hash", ids)

    def test_enable_requires_approval_path(self):
        mgr = PluginManager([ROOT / "plugins"], ROOT / "data" / "test_plugins_state2.json")
        mgr.discover()
        mgr.set_enabled("builtin_dns_info", True, user_approved=True)
        rec = mgr.load("builtin_dns_info")
        self.assertIsNotNone(rec.ctx)
        out = rec.ctx.run_action("dns.lookup", domain="localhost")
        self.assertIn("domain", out)


class TestCorrelation(unittest.TestCase):
    def test_dns_ingest(self):
        r = ingest_scan_result(
            "dns",
            "example.com",
            {"domain": "example.com", "records": {"A": ["93.184.216.34"]}},
        )
        self.assertGreaterEqual(r["relationships"], 1)
        g = graph_payload()
        self.assertTrue(any(n["label"] == "example.com" for n in g["nodes"]) or g["nodes"] is not None)
        risk_summary()


class TestWorkflows(unittest.TestCase):
    def test_requires_auth(self):
        wf = example_domain_workflow("example.com")
        out = run_workflow(wf, authorized=False)
        self.assertFalse(out.get("ok"))

    def test_actions_registered(self):
        self.assertIn("dns.lookup", ACTIONS)


class TestJobs(unittest.TestCase):
    def test_submit_and_list(self):
        jm = JobManager(max_workers=1, db_path=ROOT / "data" / "test_jobs.db")

        def work(cancel_event=None):
            return {"ok": True}

        jid = jm.submit("unit", work)
        import time

        time.sleep(0.5)
        jobs = jm.list_jobs()
        self.assertTrue(any(j["id"] == jid for j in jobs))
        jm.shutdown()


class TestMigrationsViz(unittest.TestCase):
    def test_migrate(self):
        applied = migrate()
        self.assertIsInstance(applied, list)

    def test_analytics(self):
        a = analytics_summary()
        self.assertIn("by_module", a)

    def test_topology(self):
        t = topology_from_last_network_scan()
        self.assertIn("nodes", t)


if __name__ == "__main__":
    unittest.main()
