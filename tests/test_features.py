"""Data-leak checks, cross-replica approvals, anomaly alerts, policy simulator, streaming."""
import asyncio


import litellm
import mcp_types as types
from sqlalchemy import select

from agentshield import db, gateway, llm


def ok(text="done"):
    async def f():
        return types.CallToolResult(content=[types.TextContent(type="text", text=text)])
    return f


async def agent_with(policy_yaml: str, name: str) -> dict:
    await gateway.save_policy(policy_yaml)
    policy = policy_yaml.split("\n")[0].split(":")[1].strip()
    return await gateway.auth("Bearer " + await gateway.create_agent(name, policy))


async def main():
    await db.init()

    # data-leak check on outgoing arguments
    a = await agent_with("agent: dlp\ndefault: allow\n", "dlp-agent")
    r = await gateway.guarded_call(a, "email", "send", {"body": "key is sk_live_ABCDEF123456"}, ok())
    assert r.is_error and "stripe_key" in r.content[0].text
    r = await gateway.guarded_call(a, "email", "send", {"body": "hello"}, ok())
    assert not r.is_error

    # approval decided "on another replica": only the DB row changes, no local future is resolved
    b = await agent_with("agent: appr\ndefault: approve\n", "appr-agent")

    async def other_replica():
        while not gateway._waiters:
            await asyncio.sleep(0.01)
        assert await gateway._set_status(next(iter(gateway._waiters)), "approved", "replica-2")
    r, _ = await asyncio.gather(gateway.guarded_call(b, "fs", "write", {}, ok()), other_replica())
    assert not r.is_error

    # anomaly: first use of a new tool after warm-up, and a burst of denies
    c = await agent_with("agent: anom\ndefault: allow\nrules:\n  - tool: 'x.bad'\n    action: deny\n", "anom-agent")
    for i in range(gateway.WARMUP + 1):
        await gateway.guarded_call(c, "x", "read", {"i": i}, ok())
    await gateway.guarded_call(c, "x", "export_all", {}, ok())
    for i in range(gateway.DENY_SPIKE):
        await gateway.guarded_call(c, "x", "bad", {"i": i}, ok())
    await asyncio.sleep(0.3)  # anomaly checks run in the background
    async with db.engine.connect() as conn:
        kinds = {row.kind for row in await conn.execute(select(db.alerts).where(db.alerts.c.agent_id == c["id"]))}
    assert kinds == {"new_tool", "deny_spike"}, kinds

    # simulator: tightening the policy flips the recorded x.read calls to deny
    sim = await gateway.simulate("agent: anom\ndefault: allow\nrules:\n  - tool: 'x.read'\n    action: deny\n"
                                 "  - tool: 'x.bad'\n    action: deny\n")
    assert sim["transitions"] == {"allow→deny": gateway.WARMUP + 1}, sim["transitions"]


def test_features():
    asyncio.run(main())


def test_streaming(monkeypatch):
    monkeypatch.setattr(llm, "EMBED_MODEL", None)

    async def fake_stream(model, **params):
        assert params["stream"] is True

        async def gen():
            for word in ("hel", "lo"):
                yield litellm.ModelResponseStream(model=model, choices=[{"index": 0, "delta": {"content": word}}])
        return gen()
    monkeypatch.setattr(litellm, "acompletion", fake_stream)

    async def run():
        s = await agent_with("agent: streamer\n", "stream-agent")
        out = await llm.chat(s, {"model": "some/model", "stream": True, "messages": [{"role": "user", "content": "hi"}]})
        lines = [line async for line in out]
        assert lines[-1] == "data: [DONE]\n\n" and '"hel"' in lines[0]
        async with db.engine.connect() as conn:
            row = (await conn.execute(select(db.llm_calls).where(db.llm_calls.c.agent_id == s["id"]))).first()
        assert row is not None  # logged after the stream finished
    asyncio.run(run())
