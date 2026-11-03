from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.services.rbac import (
    ensure_default_owner,
    authenticate,
    has_permission,
    require,
    set_user_role,
    create_session,
    user_from_token,
)
from app.services.audit import audit, list_audit
from app.services.projects import create_project, list_projects, user_can_access_project, assign_member
from app.services.webhooks import is_safe_webhook_url
from app.services.backup import create_backup, verify_backup, restore_backup
from app.services.license import feature_allowed, license_status, set_edition
from app.services.scheduler import add_schedule, list_schedules
from app.services.migrations import migrate
from app.services.api_server import start_api, stop_api, API_STATE
import urllib.request


class TestRBAC(unittest.TestCase):
    def test_permissions(self):
        self.assertTrue(has_permission("OWNER", "admin.full"))
        self.assertFalse(has_permission("VIEWER", "scans.run"))
        self.assertTrue(has_permission("ANALYST", "scans.run"))
        with self.assertRaises(PermissionError):
            require("VIEWER", "backup.manage")

    def test_auth_session(self):
        ensure_default_owner(password="TestOwnerPass!99")
        user = authenticate("owner", "TestOwnerPass!99")
        self.assertIsNotNone(user)
        token = create_session(user["id"])
        u2 = user_from_token(token)
        self.assertEqual(u2["username"], "owner")
        self.assertIsNone(user_from_token("bogus"))


class TestAuditProjects(unittest.TestCase):
    def test_audit(self):
        i = audit("owner", "test.action", "resource", "ok", {"password": "x", "k": 1})
        rows = list_audit(action="test.action")
        self.assertTrue(any(r["id"] == i for r in rows))
        meta = [r for r in rows if r["id"] == i][0]["meta"]
        self.assertIn("redacted", meta)

    def test_projects(self):
        pid = create_project("p5-proj", "d", actor="owner")
        self.assertTrue(user_can_access_project("owner", "OWNER", pid))
        assign_member(pid, "alice", "VIEWER")
        self.assertTrue(user_can_access_project("alice", "VIEWER", pid))
        self.assertFalse(user_can_access_project("bob", "VIEWER", pid))


class TestWebhooksBackupLicense(unittest.TestCase):
    def test_ssrf(self):
        self.assertFalse(is_safe_webhook_url("http://example.com/x")[0])
        self.assertFalse(is_safe_webhook_url("https://127.0.0.1/x")[0])
        self.assertFalse(is_safe_webhook_url("https://169.254.169.254/latest")[0])
        self.assertTrue(is_safe_webhook_url("https://example.com/hook")[0])

    def test_backup(self):
        with tempfile.TemporaryDirectory() as td:
            meta = create_backup(td)
            self.assertTrue(Path(meta["file"]).exists())
            v = verify_backup(meta["file"])
            self.assertTrue(v["ok"])
            # restore requires confirm
            self.assertFalse(restore_backup(meta["file"], confirm=False)["ok"])

    def test_license(self):
        st = license_status()
        self.assertIn(st["edition"], ("community", "professional", "enterprise"))
        self.assertTrue(feature_allowed("core"))

    def test_schedule(self):
        sid = add_schedule("tick", 30, {"workflow": "domain_basic"})
        self.assertTrue(any(s["id"] == sid for s in list_schedules()))

    def test_migrate(self):
        migrate()


class TestAPI(unittest.TestCase):
    def test_status_and_auth(self):
        start_api("127.0.0.1", 18765)
        try:
            with urllib.request.urlopen("http://127.0.0.1:18765/api/v1/status", timeout=3) as r:
                body = r.read().decode()
            self.assertIn("ok", body)
            try:
                urllib.request.urlopen("http://127.0.0.1:18765/api/v1/projects", timeout=3)
                self.fail("should 401")
            except Exception as e:
                self.assertIn("401", str(e) + str(getattr(e, "code", "")))
        finally:
            stop_api()

    def test_bind_policy(self):
        with self.assertRaises(ValueError):
            start_api("0.0.0.0", 9999)


if __name__ == "__main__":
    unittest.main()
