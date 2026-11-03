"""Optional local REST API — disabled by default, binds 127.0.0.1."""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

from app.services.assets import list_assets
from app.services.jobs import JobManager
from app.services.projects import list_projects
from app.services.rbac import has_permission, user_from_token
from app.database import list_scan_runs

API_STATE: dict[str, Any] = {
    "enabled": False,
    "host": "127.0.0.1",
    "port": 8765,
    "token": None,
    "server": None,
    "thread": None,
    "rate": {},
}


def _check_auth(handler: BaseHTTPRequestHandler) -> dict[str, Any] | None:
    auth = handler.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return user_from_token(auth[7:].strip())
    return None


def _rate_ok(ip: str, limit: int = 60) -> bool:
    import time

    now = int(time.time())
    bucket = API_STATE["rate"].setdefault(ip, [])
    API_STATE["rate"][ip] = [t for t in bucket if now - t < 60]
    if len(API_STATE["rate"][ip]) >= limit:
        return False
    API_STATE["rate"][ip].append(now)
    return True


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # quiet
        return

    def _json(self, code: int, obj: Any) -> None:
        body = json.dumps(obj, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        if not API_STATE["enabled"]:
            return self._json(503, {"error": "api disabled"})
        if not _rate_ok(self.client_address[0]):
            return self._json(429, {"error": "rate limit"})
        path = urlparse(self.path).path
        if path == "/api/v1/status":
            return self._json(200, {"ok": True, "version": "1.5.0-enterprise", "api": "v1"})
        user = _check_auth(self)
        if not user:
            return self._json(401, {"error": "unauthorized"})
        role = user["role"]
        if path == "/api/v1/projects":
            if not has_permission(role, "scans.view"):
                return self._json(403, {"error": "forbidden"})
            return self._json(200, {"projects": list_projects()})
        if path == "/api/v1/assets":
            if not has_permission(role, "assets.view"):
                return self._json(403, {"error": "forbidden"})
            return self._json(200, {"assets": list_assets()})
        if path == "/api/v1/scans":
            if not has_permission(role, "scans.view"):
                return self._json(403, {"error": "forbidden"})
            return self._json(200, {"scans": list_scan_runs(50)})
        if path == "/api/v1/tasks":
            if not has_permission(role, "scans.view"):
                return self._json(403, {"error": "forbidden"})
            jm = JobManager(max_workers=1)
            return self._json(200, {"tasks": jm.list_jobs(50)})
        return self._json(404, {"error": "not found"})

    def do_POST(self):  # noqa: N802
        if not API_STATE["enabled"]:
            return self._json(503, {"error": "api disabled"})
        if not _rate_ok(self.client_address[0]):
            return self._json(429, {"error": "rate limit"})
        length = int(self.headers.get("Content-Length", "0") or 0)
        if length > 1_000_000:
            return self._json(413, {"error": "payload too large"})
        user = _check_auth(self)
        if not user:
            return self._json(401, {"error": "unauthorized"})
        path = urlparse(self.path).path
        if path.startswith("/api/v1/tasks/") and path.endswith("/cancel"):
            if not has_permission(user["role"], "workflows.run"):
                return self._json(403, {"error": "forbidden"})
            tid = path.split("/")[4]
            jm = JobManager(max_workers=1)
            ok = jm.cancel(tid)
            return self._json(200, {"cancelled": ok, "id": tid})
        return self._json(404, {"error": "not found"})


def start_api(host: str = "127.0.0.1", port: int = 8765) -> dict[str, Any]:
    if host not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError("API may only bind to localhost by default policy")
    if API_STATE["server"]:
        return {"ok": True, "already": True}
    server = ThreadingHTTPServer((host, port), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    API_STATE.update({"enabled": True, "host": host, "port": port, "server": server, "thread": thread})
    return {"ok": True, "host": host, "port": port}


def stop_api() -> None:
    srv = API_STATE.get("server")
    if srv:
        try:
            srv.shutdown()
        except Exception:
            pass
        try:
            srv.server_close()
        except Exception:
            pass
    API_STATE.update({"enabled": False, "server": None, "thread": None})
