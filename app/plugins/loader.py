"""Plugin discovery, validation, and isolated loading."""
from __future__ import annotations

import importlib.util
import json
import logging
import sys
from pathlib import Path
from typing import Any

from app.plugins.base import ALLOWED_PERMISSIONS, Plugin, PluginContext, PluginManifest

log = logging.getLogger("bruta_x.plugins")


class PluginRecord:
    def __init__(self, manifest: PluginManifest, path: Path, enabled: bool = False):
        self.manifest = manifest
        self.path = path
        self.enabled = enabled
        self.instance: Plugin | None = None
        self.error: str | None = None
        self.ctx: PluginContext | None = None


class PluginManager:
    def __init__(self, search_paths: list[Path], state_path: Path):
        self.search_paths = search_paths
        self.state_path = state_path
        self.plugins: dict[str, PluginRecord] = {}
        self._state = self._load_state()

    def _load_state(self) -> dict[str, Any]:
        if self.state_path.exists():
            try:
                return json.loads(self.state_path.read_text(encoding="utf-8"))
            except Exception:
                return {"enabled": {}}
        return {"enabled": {}}

    def save_state(self) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        enabled = {pid: rec.enabled for pid, rec in self.plugins.items()}
        self.state_path.write_text(json.dumps({"enabled": enabled}, indent=2), encoding="utf-8")

    def discover(self) -> list[PluginRecord]:
        found: list[PluginRecord] = []
        for root in self.search_paths:
            if not root.exists():
                continue
            for manifest_path in root.glob("*/plugin.json"):
                try:
                    data = json.loads(manifest_path.read_text(encoding="utf-8"))
                    m = PluginManifest(
                        id=data["id"],
                        name=data.get("name", data["id"]),
                        description=data.get("description", ""),
                        version=data.get("version", "0.0.0"),
                        author=data.get("author", "unknown"),
                        min_app_version=data.get("min_app_version", "1.0.0"),
                        permissions=list(data.get("permissions") or []),
                        entry=data.get("entry", "plugin.py"),
                        enabled_by_default=bool(data.get("enabled_by_default", False)),
                    )
                    errs = m.validate()
                    rec = PluginRecord(m, manifest_path.parent)
                    if errs:
                        rec.error = "; ".join(errs)
                    # explicit enable only — defaults off unless previously enabled or builtin default + user state
                    prev = self._state.get("enabled", {}).get(m.id)
                    if prev is None:
                        rec.enabled = False  # never auto-enable third-party
                    else:
                        rec.enabled = bool(prev)
                    self.plugins[m.id] = rec
                    found.append(rec)
                except Exception as e:
                    log.exception("manifest error %s", manifest_path)
                    bad = PluginRecord(
                        PluginManifest("invalid", "invalid", str(e), "0", "unknown"),
                        manifest_path.parent,
                    )
                    bad.error = str(e)
                    found.append(bad)
        return found

    def set_enabled(self, plugin_id: str, enabled: bool, *, user_approved: bool) -> None:
        rec = self.plugins[plugin_id]
        if enabled and not user_approved:
            raise PermissionError("Enabling plugins requires explicit user approval")
        if enabled and rec.error:
            raise RuntimeError(f"cannot enable invalid plugin: {rec.error}")
        for perm in rec.manifest.permissions:
            if perm not in ALLOWED_PERMISSIONS:
                raise PermissionError(f"disallowed permission: {perm}")
        rec.enabled = enabled
        self.save_state()
        if enabled:
            self.load(plugin_id)
        else:
            rec.instance = None
            rec.ctx = None

    def load(self, plugin_id: str) -> PluginRecord:
        rec = self.plugins[plugin_id]
        if not rec.enabled:
            raise RuntimeError("plugin not enabled")
        entry = rec.path / (rec.manifest.entry if rec.manifest.entry.endswith(".py") else "plugin.py")
        if not entry.exists():
            entry = rec.path / "plugin.py"
        try:
            spec = importlib.util.spec_from_file_location(f"bruta_plugin_{plugin_id}", entry)
            if not spec or not spec.loader:
                raise ImportError("cannot load plugin module")
            mod = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = mod
            spec.loader.exec_module(mod)
            plugin_obj: Plugin = mod.create_plugin()
            ctx = PluginContext(log, {})
            plugin_obj.register(ctx)
            rec.instance = plugin_obj
            rec.ctx = ctx
            rec.error = None
            log.info("loaded plugin %s", plugin_id)
        except Exception as e:
            rec.error = str(e)
            rec.instance = None
            log.exception("plugin load failed %s", plugin_id)
        return rec

    def list_plugins(self) -> list[dict[str, Any]]:
        out = []
        for pid, rec in self.plugins.items():
            d = rec.manifest.to_dict()
            d["enabled"] = rec.enabled
            d["error"] = rec.error
            d["path"] = str(rec.path)
            out.append(d)
        return out
