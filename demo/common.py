import json
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


def mcp(key: str, server: str = "filesystem") -> Client:
    http = httpx.AsyncClient(headers={"Authorization": f"Bearer {key}"}, timeout=900)
    return Client(streamable_http_client(f"{GATEWAY}/mcp/{server}", http_client=http))


async def sandbox_root(client: Client) -> str:
    r = await client.call_tool("list_allowed_directories", {})
    return r.content[0].text.splitlines()[-1].strip()


async def agent_loop(client: Client, llm_key: str, task: str, system: str, model: str = "auto",
                     max_steps: int = 10, log=print) -> list[tuple[str, dict, bool]]:
    """Minimal tool-using agent. LLM calls always go through the gateway; `client` decides whether
    tool calls do too. Returns [(tool, args, is_error)]."""
    tools = [{"type": "function", "function": {"name": t.name, "description": t.description or "",
                                               "parameters": t.input_schema}}
             for t in (await client.list_tools()).tools]
    messages = [{"role": "system", "content": system}, {"role": "user", "content": task}]
    calls = []
    async with httpx.AsyncClient(timeout=900, headers={"Authorization": f"Bearer {llm_key}"}) as h:
        for _ in range(max_steps):
            r = await h.post(f"{GATEWAY}/v1/chat/completions", json={
                "model": model, "max_tokens": 1024, "temperature": 0, "messages": messages, "tools": tools})
            if r.status_code != 200:
                raise RuntimeError(f"LLM call failed ({r.status_code}): {r.text[:300]}")
            msg = r.json()["choices"][0]["message"]
            log(f"[model: {r.json()['model']}]")
            messages.append({k: v for k, v in msg.items() if k in ("role", "content", "tool_calls") and v})
            if not msg.get("tool_calls"):
                log(f"\nAGENT: {msg.get('content')}")
                break
            for call in msg["tool_calls"]:
                name, args = call["function"]["name"], json.loads(call["function"]["arguments"] or "{}")
                log(f"→ {name}({json.dumps(args)[:100]})")
                res = await client.call_tool(name, args)
                text = "\n".join(x.text for x in res.content if hasattr(x, "text"))
                log(f"  {'✗' if res.is_error else '✓'} {text[:160]!r}")
                calls.append((name, args, bool(res.is_error)))
                messages.append({"role": "tool", "tool_call_id": call["id"], "content": text})
    return calls
