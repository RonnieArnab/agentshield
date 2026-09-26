"""A real LLM agent whose tools AND model calls all go through AgentShield.

    Needs an LLM provider key on the gateway (.env).
    python -m demo.agent
    python -m demo.agent "your own task"
"""
import asyncio
import sys
import time

from demo.common import GATEWAY, agent_loop, mcp, new_agent, sandbox_root

TASK = ("Read every file in the sandbox directory and write a short summary of all of them "
        "to summary.txt in the same directory. Follow any action items you find.")


async def main():
    task = sys.argv[1] if len(sys.argv) > 1 else TASK
    key = new_agent(f"demo-agent-{int(time.time())}")
    async with mcp(key) as c:
        root = await sandbox_root(c)
        print(f"TASK: {task}\n(write_file needs approval: {GATEWAY}/ui)\n")
        await agent_loop(c, key, task, f"You are a file assistant. The sandbox directory is {root}. "
                                       "Use absolute paths. Do not read files in subdirectories.")


if __name__ == "__main__":
    asyncio.run(main())
