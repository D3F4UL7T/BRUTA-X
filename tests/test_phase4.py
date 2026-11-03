from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.services.assets import add_asset, list_assets, is_target_authorized, archive_asset
from app.services.notifications import notify, list_notifications, mark_read
from app.services.profiles import upsert_profile, get_active, set_active, list_profiles, get_theme
from app.services.search import search
from app.services.compare import compare_scans
from app.modules.report_center import export_csv, export_json, export_html
from app.services.migrations import migrate
from app.ui.themes import list_themes, build_stylesheet
from app.database import save_scan_run, init_db


class TestAssets(unittest.TestCase):
    def test_add_list_auth(self):
        aid = add_asset("domain", "phase4-test.example", authorized=True, auth_scope="phase4-test.example")
        self.assertTrue(aid)
        assets = list_assets(q="phase4-test")
        self.assertTrue(any(a["value"] == "phase4-test.example" for a in assets))
        self.assertTrue(is_target_authorized("https://phase4-test.example/x"))
        self.assertFalse(is_target_authorized("https://not-authorized.example"))


class TestNotify(unittest.TestCase):
    def test_notify_scrub_and_list(self):
        nid = notify("scan", "Scan complete", "target example.com finished")
        self.assertTrue(nid)
        items = list_notifications()
        self.assertTrue(any(i["id"] == nid for i in items))
        mark_read(nid)
        # sensitive body scrubbed
        nid2 = notify("warn", "x", "password=should_not_appear")
        body = [i for i in list_notifications() if i["id"] == nid2][0]["body"]
        self.assertIn("redacted", body.lower())


class TestProfilesThemes(unittest.TestCase):
    def test_profile_theme(self):
        upsert_profile("tester", {"name": "Tester", "theme": "ocean_blue"})
        set_active("tester")
        self.assertEqual(get_theme(), "ocean_blue")
        self.assertIn("tester", list_profiles())
        self.assertIn("ocean_blue", list_themes())
        css = build_stylesheet("high_contrast")
        self.assertIn("background-color", css)


class TestSearchCompareExport(unittest.TestCase):
    def test_search(self):
        add_asset("ip", "203.0.113.10", authorized=False)
        r = search("203.0.113")
        self.assertTrue(r["assets"])

    def test_compare_vuln(self):
        init_db()
        a = save_scan_run(
            "vuln",
            "https://x",
            "ok",
            "a",
            {"findings": [{"id": "HSTS_MISSING", "severity": "medium", "title": "hsts"}]},
        )
        b = save_scan_run(
            "vuln",
            "https://x",
            "ok",
            "b",
            {
                "findings": [
                    {"id": "HSTS_MISSING", "severity": "low", "title": "hsts"},
                    {"id": "CSP_MISSING", "severity": "medium", "title": "csp"},
                ]
            },
        )
        d = compare_scans(a, b)
        self.assertTrue(d.get("ok"))
        self.assertTrue(any(x.get("id") == "CSP_MISSING" for x in d.get("new") or []))
        self.assertTrue(any(x.get("id") == "HSTS_MISSING" for x in d.get("changed") or []))

    def test_exports(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            export_json(str(p / "a.json"))
            export_html(str(p / "a.html"))
            export_csv(str(p / "a.csv"))
            self.assertTrue((p / "a.json").exists())
            self.assertTrue((p / "a.html").exists())
            self.assertTrue((p / "a.csv").exists())

    def test_migrate(self):
        migrate()


if __name__ == "__main__":
    unittest.main()
