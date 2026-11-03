# BRUTA X Plugin Development

## Manifest (`plugin.json`)

```json
{
  "id": "my_plugin",
  "name": "My Plugin",
  "description": "...",
  "version": "1.0.0",
  "author": "You",
  "min_app_version": "1.2.0",
  "permissions": ["net.dns.read"],
  "entry": "plugin.py",
  "enabled_by_default": false
}
```

Allowed permissions: `net.dns.read`, `net.http.public`, `fs.hash.read`, `ui.notify`, `data.scan_history.read`.

## Entry point

```python
from app.plugins.base import Plugin, PluginContext, PluginManifest

class MyPlugin(Plugin):
    manifest = PluginManifest(...)
    def register(self, ctx: PluginContext) -> None:
        ctx.register_action("my.action", lambda **kw: {...})

def create_plugin():
    return MyPlugin()
```

## Security

- Plugins are **disabled** until the user enables them in Plugin Center.
- Invalid permissions or manifests refuse to load.
- Failures are isolated; they do not crash the host process intentionally.
- Do not ship secrets inside plugins.
