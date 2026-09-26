import asyncio
import os
import pathlib
import tempfile

os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{tempfile.mkdtemp()}/t.db"

import litellm  # noqa: E402

from agentshield import db, gateway, llm  # noqa: E402
from agentshield.gateway import Denied  # noqa: E402

calls = []


async def fake_completion(model, **params):
    calls.append((model, params))
    return litellm.ModelResponse(model=model, choices=[{"message": {"role": "assistant", "content": "hi"}}],
                                 usage={"prompt_tokens": 10, "completion_tokens": 2, "total_tokens": 12})


def test_difficulty():
    assert llm.difficulty({"messages": [{"role": "user", "content": "hello"}]}) == "easy"
    assert llm.difficulty({"messages": [{"role": "user", "content": "```py\ndef f(): pass```"}]}) == "medium"
    assert llm.difficulty({"messages": [{"role": "user", "content": "prove this theorem: " + "x" * 5000}]}) == "hard"


def test_chat_routes_filters_and_budgets(monkeypatch):
    monkeypatch.setattr(litellm, "acompletion", fake_completion)
    monkeypatch.setattr(llm, "EMBED_MODEL", None)  # litellm auto-loads .env; keep the cache off here
    monkeypatch.setattr(litellm, "completion_cost", lambda completion_response: 3.0)

    async def main():
        await db.init()
        await gateway.save_policy(pathlib.Path("policies/support-bot.yaml").read_text())  # downgrade on budget
        await gateway.save_policy("agent: strict\non_budget_exceeded: block\n")
        a = await gateway.auth("Bearer " + await gateway.create_agent("a", "support-bot", daily=5))
        b = await gateway.auth("Bearer " + await gateway.create_agent("b", "strict", daily=5))
        msg = {"messages": [{"role": "user", "content": "prove the theorem " + "x" * 5000}], "api_base": "http://evil"}

        out = await llm.chat(a, {"model": "auto", **msg})
        assert out["choices"][0]["message"]["content"] == "hi"
        assert calls[-1][0] == llm.TIERS["hard"] and "api_base" not in calls[-1][1]

        await llm.chat(a, {"model": "auto", **msg})  # spend now 6 > 5 -> over budget
        await llm.chat(a, {"model": "auto", **msg})
        assert calls[-1][0] == llm.TIERS["easy"]  # downgraded

        await llm.chat(b, {"model": "auto", **msg})
        await llm.chat(b, {"model": "auto", **msg})
        try:
            await llm.chat(b, {"model": "auto", **msg})
            raise AssertionError("should block")
        except Denied as e:
            assert e.status == 402

    asyncio.run(main())
