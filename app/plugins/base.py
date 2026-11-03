"""Plugin development API — base types and metadata."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Callable


ALLOWED_PERMISSIONS = frozenset(
    {
        "net.dns.read",
        "net.http.public",
        "fs.hash.read",
        "ui.notify",
        "data.scan_history.read",
    }
)


@dataclass
class PluginManifest:
    id: str
    name: str
    description: str
    version: str
    author: str
    min_app_version: str = "1.2.0"
    permissions: list[str] = field(default_factory=list)
    entry: str = "plugin:register"
    enabled_by_default: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def validate(self) -> list[str]:
        errs: list[str] = []
        if not self.id or not self.id.replace("_", "").replace("-", "").isalnum():
            errs.append("invalid plugin id")
        if not self.name:
            errs.append("missing name")
        if not self.version:
            errs.append("missing version")
        for p in self.permissions:
            if p not in ALLOWED_PERMISSIONS:
                errs.append(f"permission not allowed: {p}")
        return errs


class PluginContext:
    def __init__(self, logger, settings: dict[str, Any]):
        self.logger = logger
        self.settings = settings
        self._actions: dict[str, Callable[..., Any]] = {}

    def register_action(self, name: str, fn: Callable[..., Any]) -> None:
        self._actions[name] = fn

    def run_action(self, name: str, **kwargs: Any) -> Any:
        if name not in self._actions:
            raise KeyError(f"action not registered: {name}")
        return self._actions[name](**kwargs)


class Plugin:
    """Override register() to attach actions."""

    manifest: PluginManifest

    def register(self, ctx: PluginContext) -> None:  # pragma: no cover - interface
        raise NotImplementedError
