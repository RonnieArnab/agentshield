import os

import httpx
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

GATEWAY = os.getenv("GATEWAY_URL", "http://localhost:8000")
ADMIN = {"Authorization": f"Bearer {os.getenv('ADMIN_KEY', 'change-me')}"}


def new_agent(name: str, policy: str = "demo-bot") -> str:
    r = httpx.post(f"{GATEWAY}/agents", headers=ADMIN, json={"name": name, "policy": policy})
    r.raise_for_status()
    return r.json()["api_key"]


def mcp(key: str) -> Client:
    http = httpx.AsyncClient(headers={"Authorization": f"Bearer {key}"}, timeout=900)
    return Client(streamable_http_client(f"{GATEWAY}/mcp/filesystem", http_client=http))


async def sandbox_root(client: Client) -> str:
    r = await client.call_tool("list_allowed_directories", {})
    return r.content[0].text.splitlines()[-1].strip()
