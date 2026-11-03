from app.plugins.base import Plugin, PluginContext, PluginManifest
from app.modules.file_analyzer import analyze_file


class FileHashPlugin(Plugin):
    manifest = PluginManifest(
        id="builtin_file_hash",
        name="File Hash Plugin",
        description="File hashing action",
        version="1.0.0",
        author="BRUTA Technologies",
        permissions=["fs.hash.read"],
    )

    def register(self, ctx: PluginContext) -> None:
        def file_hash(path: str):
            return analyze_file(path).to_dict()

        ctx.register_action("file.hash", file_hash)


def create_plugin() -> Plugin:
    return FileHashPlugin()
