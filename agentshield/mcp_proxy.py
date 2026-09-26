"""One MCP server per upstream at /mcp/{name}: agents see an MCP server, upstreams see an MCP client."""

import json
import logging
import os
from contextlib import AsyncExitStack

import mcp_types as types
import yaml
from mcp import Client, StdioServerParameters
from mcp.server import Server
from mcp.server.transport_security import TransportSecuritySettings
from starlette.routing import Route

from .detect import rule_scan
from .gateway import QUARANTINED, Denied, auth, get_policy, guarded_call
from .policy import visible


log = logging.getLogger("agentshield")


def scan_tools(server: str, tools) -> list:
    """Tool-poisoning check: quarantine tools whose description or schema carries injected instructions.
    Runs on every listing, so a server that changes a description later (rug pull) is caught too."""
    clean = []
    for t in tools:
        full = f"{server}.{t.name}"
        if hits := rule_scan(f"{t.description or ''}\n{json.dumps(t.input_schema)}"):
            if full not in QUARANTINED:
                QUARANTINED.add(full)
                log.warning("QUARANTINED tool %s: poisoned description (%s)", full, ", ".join(hits))
        elif full not in QUARANTINED:
            clean.append(t)
    return clean


def load_servers(path: str) -> dict:
    with open(path) as f:
        return (yaml.safe_load(f) or {}).get("servers") or {}


def upstream(cfg: dict) -> Client:
    if "url" in cfg:
        return Client(cfg["url"])
    return Client(StdioServerParameters(command=cfg["command"], args=cfg.get("args", []),
                                        env={**os.environ, **cfg.get("env", {})}))


async def _agent(ctx) -> dict:
    headers = getattr(ctx.request, "headers", None) or {}
    return await auth(headers.get("authorization"))


def proxy_server(name: str, client: Client) -> Server:
    async def list_tools(ctx, params):
        policy = await get_policy((await _agent(ctx))["policy"])
        tools = scan_tools(name, (await client.list_tools()).tools)
        return types.ListToolsResult(tools=[t for t in tools if visible(policy, f"{name}.{t.name}")])

    async def call_tool(ctx, params: types.CallToolRequestParams):
        try:
            agent = await _agent(ctx)
        except Denied as e:
            return types.CallToolResult(content=[types.TextContent(type="text", text=str(e))], is_error=True)
        args = params.arguments or {}
        return await guarded_call(agent, name, params.name, args, lambda: client.call_tool(params.name, args))

    return Server(f"agentshield-{name}", on_list_tools=list_tools, on_call_tool=call_tool)


async def mount_all(app, stack: AsyncExitStack, config_path: str) -> list[str]:
    """Connect to every upstream, add a /mcp/{name} route per server, run their session managers."""
    hosts = os.getenv("MCP_ALLOWED_HOSTS", "127.0.0.1:*,localhost:*").split(",")
    # "*" = public deployment behind its own domain: skip Host checks (agents still need an API key)
    security = TransportSecuritySettings(enable_dns_rebinding_protection=hosts != ["*"], allowed_hosts=hosts,
                                         allowed_origins=[f"http://{h}" for h in hosts] + [f"https://{h}" for h in hosts])
    names = []
    for name, cfg in load_servers(config_path).items():
        client = await stack.enter_async_context(upstream(cfg))
        scan_tools(name, (await client.list_tools()).tools)  # quarantine poisoned tools up front
        sub = proxy_server(name, client).streamable_http_app(streamable_http_path=f"/mcp/{name}",
                                                             transport_security=security)
        app.router.routes.extend(r for r in sub.routes if isinstance(r, Route))
        await stack.enter_async_context(sub.router.lifespan_context(sub))
        names.append(name)
    return names
