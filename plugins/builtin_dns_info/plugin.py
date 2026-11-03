from app.plugins.base import Plugin, PluginContext, PluginManifest
from app.modules.dns_intelligence import query_dns


class DnsInfoPlugin(Plugin):
    manifest = PluginManifest(
        id="builtin_dns_info",
        name="DNS Info Plugin",
        description="DNS resolution action",
        version="1.0.0",
        author="BRUTA Technologies",
        permissions=["net.dns.read"],
    )

    def register(self, ctx: PluginContext) -> None:
        def dns_lookup(domain: str):
            return query_dns(domain).to_dict()

        ctx.register_action("dns.lookup", dns_lookup)


def create_plugin() -> Plugin:
    return DnsInfoPlugin()
