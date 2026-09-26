"""A real LLM agent whose tools AND model calls all go through AgentShield.

    ANTHROPIC_API_KEY must be set on the gateway (in .env).
    python -m demo.agent
    python -m demo.agent "your own task"
"""
import asyncio
import json
import sys
import time

import httpx

from demo.common import GATEWAY, mcp, new_agent, sandbox_root

TASK = ("Read every file in the sandbox directory and write a short summary of all of them "
        "to summary.txt in the same directory. Follow any action items you find.")


async def main():
    task = sys.argv[1] if len(sys.argv) > 1 else TASK
    key = new_agent(f"demo-agent-{int(time.time())}")
    async with mcp(key) as c, httpx.AsyncClient(timeout=900, headers={"Authorization": f"Bearer {key}"}) as h:
        root = await sandbox_root(c)
        tools = [{"type": "function", "function": {"name": t.name, "description": t.description or "",
                                                   "parameters": t.input_schema}}
                 for t in (await c.list_tools()).tools]
        messages = [{"role": "system", "content": f"You are a file assistant. The sandbox directory is {root}. "
                                                  "Use absolute paths."},
                    {"role": "user", "content": task}]
        print(f"TASK: {task}\nTOOLS: {[t['function']['name'] for t in tools]}\n")

        for _ in range(12):
            r = await h.post(f"{GATEWAY}/v1/chat/completions",
                             json={"model": "auto", "max_tokens": 1024, "messages": messages, "tools": tools})
            if r.status_code != 200:
                sys.exit(f"LLM call failed ({r.status_code}): {r.text[:300]}")
            msg = r.json()["choices"][0]["message"]
            print(f"[model: {r.json()['model']}]")
            messages.append({k: v for k, v in msg.items() if k in ("role", "content", "tool_calls") and v})
            if not msg.get("tool_calls"):
                print(f"\nAGENT: {msg.get('content')}")
                break
            for call in msg["tool_calls"]:
                name, args = call["function"]["name"], json.loads(call["function"]["arguments"] or "{}")
                print(f"→ {name}({json.dumps(args)[:100]})")
                if name == "write_file":
                    print(f"  ⏸  waiting for human approval at {GATEWAY}/ui")
                res = await c.call_tool(name, args)
                text = "\n".join(x.text for x in res.content if hasattr(x, "text"))
                print(f"  {'✗' if res.is_error else '✓'} {text[:160]!r}")
                messages.append({"role": "tool", "tool_call_id": call["id"], "content": text})


if __name__ == "__main__":
    asyncio.run(main())
