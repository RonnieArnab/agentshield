"""LLM path: budget -> route by difficulty -> semantic cache -> provider (via LiteLLM) -> audit.
Supports stream=true (server-sent events, logged with usage when the stream ends)."""
import asyncio
import json
import math
import os
import re
import time

import anyio
import litellm
from prometheus_client import Counter
from sqlalchemy import func, insert, select

from . import db, state
from .detect import STRIPPED, has_pii, redact_secrets, scan, strip_injections
from .gateway import INJECTIONS, WARNING, Denied, check_rate, get_policy, notify

TIERS = {
    "easy": os.getenv("MODEL_EASY", "anthropic/claude-haiku-4-5"),
    "medium": os.getenv("MODEL_MEDIUM", "anthropic/claude-sonnet-5"),
    "hard": os.getenv("MODEL_HARD", "anthropic/claude-opus-5-5"),
}
ORDER = ["easy", "medium", "hard"]
EMBED_MODEL = os.getenv("EMBED_MODEL")  # e.g. text-embedding-3-small; unset = cache off
SIMILARITY = float(os.getenv("CACHE_SIMILARITY", 0.95))
# Only these request fields reach the provider: never let a caller set api_base / api_key.
PASSTHROUGH = {"messages", "temperature", "max_tokens", "max_completion_tokens", "top_p", "stop", "tools",
               "tool_choice", "response_format", "n", "seed", "user"}

LLM_CALLS = Counter("agentshield_llm_calls_total", "LLM calls", ["agent", "tier", "cache_hit"])
LLM_COST = Counter("agentshield_llm_cost_usd_total", "LLM spend in USD", ["agent"])


def _text(body: dict) -> str:
    parts = []
    for m in body.get("messages", []):
        c = m.get("content")
        if isinstance(c, str):
            parts.append(c)
        elif isinstance(c, list):
            parts += [p.get("text", "") for p in c if isinstance(p, dict)]
    return "\n".join(parts)


_CODE = re.compile(r"```|\bdef \w+\(|\bclass \w+|function\s*\w*\(|#include|\bSELECT\b.+\bFROM\b", re.I | re.S)
_MATH = re.compile(r"\\(frac|sum|int)|\bprove\b|\btheorem\b|\bderivative\b|\bintegral\b|\bequation\b", re.I)


def difficulty(body: dict) -> str:
    # ponytail: rule-based scorer; replace with a small trained classifier once routing mistakes are measured.
    t = _text(body)
    score = (len(t) > 4000) + (len(t) > 16000) + bool(_CODE.search(t)) + bool(_MATH.search(t)) \
        + (len(body.get("tools") or []) > 3)
    return ORDER[min(score, 2)]


# ---- budgets -----------------------------------------------------------------------------

async def budget_state(agent: dict) -> str:
    now = db.now()
    day = now.replace(hour=0, minute=0, second=0, microsecond=0)
    month = day.replace(day=1)
    async with db.engine.connect() as c:
        q = select(func.coalesce(func.sum(db.llm_calls.c.cost_usd), 0.0)).where(db.llm_calls.c.agent_id == agent["id"])
        spent_d = (await c.execute(q.where(db.llm_calls.c.created_at >= day))).scalar()
        spent_m = (await c.execute(q.where(db.llm_calls.c.created_at >= month))).scalar()
    frac = max(spent_d / agent["daily_budget_usd"], spent_m / agent["monthly_budget_usd"])
    if frac >= 1:
        return "over"
    if frac >= 0.8:
        if await state.once(f"budget:{agent['id']}:{day.date()}", 86400):
            await notify(f":money_with_wings: agent *{agent['name']}* has used {frac:.0%} of its LLM budget")
        return "warn"
    return "ok"


# ---- semantic cache ----------------------------------------------------------------------

def cacheable(body: dict) -> bool:
    return bool(EMBED_MODEL) and not body.get("tools") and not body.get("stream") and \
        all(m.get("role") != "tool" for m in body.get("messages", [])) and not has_pii(_text(body))


async def embed(text: str) -> list[float]:
    v = (await litellm.aembedding(model=EMBED_MODEL, input=[text[:8000]])).data[0]["embedding"]
    n = math.sqrt(sum(x * x for x in v)) or 1.0
    return [x / n for x in v]


# ---- guards for chatbots and RAG --------------------------------------------------------
GUARDED_ROLES = {"user", "tool"}  # system prompts are the developer's own, so trusted


async def _clean(text: str, policy) -> tuple[str, int, list[str]]:
    thr = policy.injection_threshold
    score, reasons = await scan(text, thr)
    if score < thr:
        return text, 0, []
    mode = policy.on_prompt_injection
    if mode == "warn":
        return f"{WARNING}\n\n{text}", 0, reasons
    if mode == "strip":
        new, n, why = await asyncio.to_thread(strip_injections, text, thr)
        if n and (await scan(new.replace(STRIPPED, ""), thr))[0] < thr:
            return new, n, why
    raise Denied(f"request contains a prompt injection ({', '.join(reasons)})", 400)


async def guard_input(policy, messages: list) -> tuple[list, dict]:
    """Scan user and tool messages (where RAG context and pasted content live) for injection."""
    if policy.on_prompt_injection == "allow":
        return messages, {}
    out, removed, reasons = [], 0, set()
    for m in messages:
        m = dict(m)
        if m.get("role") in GUARDED_ROLES:
            c = m.get("content")
            if isinstance(c, str):
                m["content"], n, r = await _clean(c, policy)
                removed, reasons = removed + n, reasons | set(r)
            elif isinstance(c, list):  # multi-part content: guard each text part
                parts = []
                for p in c:
                    if isinstance(p, dict) and p.get("type") == "text":
                        t, n, r = await _clean(p.get("text", ""), policy)
                        p, removed, reasons = {**p, "text": t}, removed + n, reasons | set(r)
                    parts.append(p)
                m["content"] = parts
        out.append(m)
    if not reasons:
        return out, {}
    return out, {"input": {"action": policy.on_prompt_injection, "paragraphs_removed": removed,
                           "reasons": sorted(reasons)}}


def guard_output(policy, out: dict) -> dict:
    """Mask or withhold secrets and card numbers in the model's answer."""
    if policy.on_output_leak == "allow":
        return {}
    found = set()
    for ch in out.get("choices") or []:
        msg = ch.get("message") or {}
        if isinstance(msg.get("content"), str):
            clean, kinds = redact_secrets(msg["content"])
            if kinds:
                found |= set(kinds)
                msg["content"] = clean if policy.on_output_leak == "mask" else \
                    f"[response withheld by AgentShield: it contained {', '.join(kinds)}]"
    return {"output": {"action": policy.on_output_leak, "kinds": sorted(found)}} if found else {}


# ---- the call ----------------------------------------------------------------------------

async def chat(agent: dict, body: dict):
    """-> response dict, or an async iterator of SSE lines when body["stream"] is true."""
    t0 = time.perf_counter()
    if not body.get("messages"):
        raise Denied("messages is required", 400)
    await check_rate(agent["id"])
    policy = await get_policy(agent["policy"])
    messages, report = await guard_input(policy, body["messages"])
    if report:
        INJECTIONS.labels(agent["name"]).inc()
        body = {**body, "messages": messages}
    requested = body.get("model") or "auto"
    tier = difficulty(body) if requested == "auto" else None
    model = TIERS[tier] if tier else requested

    budget = await budget_state(agent)
    if budget == "over":
        if policy.on_budget_exceeded == "block":
            raise Denied("LLM budget exhausted", 402)
        tier, model = "easy", TIERS["easy"]

    rec = dict(agent_id=agent["id"], model_requested=requested, tier=tier, cache_hit=False,
               tokens_in=0, tokens_out=0, cost_usd=0.0, guard=json.dumps(report) if report else None)
    vec = None
    if cacheable(body):
        vec = await embed(_text(body))
        if hit := await state.cache_get(agent["id"], requested, vec, SIMILARITY):
            rec.update(model_used=hit.get("model"), cache_hit=True, latency_ms=(time.perf_counter() - t0) * 1000)
            await _log(agent, rec)
            return hit

    params = {k: v for k, v in body.items() if k in PASSTHROUGH}
    stream = bool(body.get("stream"))
    if stream:
        params.update(stream=True, stream_options={"include_usage": True})
    while True:  # errors before the first token retry one tier up
        try:
            resp = await litellm.acompletion(model=model, **params)
            break
        except Exception:
            if not tier or tier == "hard" or budget == "over":
                raise
            tier = ORDER[ORDER.index(tier) + 1]
            model = TIERS[tier]
    rec.update(model_used=model, tier=tier)

    if stream:  # ponytail: no output masking on streams (a secret can span chunks); buffer if you need it
        return _stream(agent, rec, resp, params["messages"], t0)

    out = resp.model_dump()
    if leak := guard_output(policy, out):
        report.update(leak)
        rec["guard"] = json.dumps(report)
    if report:
        out["agentshield"] = report  # extra field; OpenAI-compatible clients ignore it
    await _finish(agent, rec, resp, out.get("usage") or {}, t0)
    if vec is not None:
        await state.cache_put(agent["id"], requested, vec, out)
    return out


async def _stream(agent, rec, resp, messages, t0):
    chunks = []
    try:
        async for ch in resp:
            chunks.append(ch)
            yield f"data: {ch.model_dump_json(exclude_none=True)}\n\n"
        yield "data: [DONE]\n\n"
    finally:
        with anyio.CancelScope(shield=True):  # log what was streamed even if the client hung up
            full = litellm.stream_chunk_builder(chunks, messages=messages) if chunks else None
            usage = (full.model_dump().get("usage") or {}) if full else {}
            await _finish(agent, rec, full, usage, t0)


async def _finish(agent, rec, resp, usage, t0):
    try:
        cost = litellm.completion_cost(completion_response=resp) if resp is not None else 0.0
    except Exception:
        cost = 0.0  # unknown model price
    rec.update(tokens_in=usage.get("prompt_tokens", 0), tokens_out=usage.get("completion_tokens", 0),
               cost_usd=cost, latency_ms=(time.perf_counter() - t0) * 1000)
    await _log(agent, rec)


async def _log(agent, rec):
    LLM_CALLS.labels(agent["name"], rec["tier"] or "explicit", str(rec["cache_hit"])).inc()
    LLM_COST.labels(agent["name"]).inc(rec["cost_usd"])
    async with db.engine.begin() as c:
        await c.execute(insert(db.llm_calls).values(**rec))
