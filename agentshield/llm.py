"""LLM path: budget -> route by difficulty -> semantic cache -> provider (via LiteLLM) -> audit."""
import math
import os
import re
import time
from collections import defaultdict, deque

import litellm
from prometheus_client import Counter
from sqlalchemy import func, insert, select

from . import db
from .detect import has_pii
from .gateway import Denied, check_rate, get_policy, notify

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
_alerted: set = set()


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
        if (agent["id"], day) not in _alerted:
            _alerted.add((agent["id"], day))
            await notify(f":money_with_wings: agent *{agent['name']}* has used {frac:.0%} of its LLM budget")
        return "warn"
    return "ok"


# ---- semantic cache ----------------------------------------------------------------------
# ponytail: in-process brute-force cosine over the last 1000 entries per agent;
# move to Redis vector search for replicas or bigger caches.
_cache: dict[int, deque] = defaultdict(lambda: deque(maxlen=1000))


def cacheable(body: dict) -> bool:
    return bool(EMBED_MODEL) and not body.get("tools") and \
        all(m.get("role") != "tool" for m in body.get("messages", [])) and not has_pii(_text(body))


async def embed(text: str) -> list[float]:
    v = (await litellm.aembedding(model=EMBED_MODEL, input=[text[:8000]])).data[0]["embedding"]
    n = math.sqrt(sum(x * x for x in v)) or 1.0
    return [x / n for x in v]


def lookup(agent_id: int, model: str, v: list[float]):
    best, hit = SIMILARITY, None
    for m, vec, resp in _cache[agent_id]:
        if m == model and (s := sum(a * b for a, b in zip(v, vec))) >= best:
            best, hit = s, resp
    return hit


# ---- the call ----------------------------------------------------------------------------

async def chat(agent: dict, body: dict) -> dict:
    t0 = time.perf_counter()
    if body.get("stream"):
        raise Denied("streaming is not supported yet; send stream=false", 400)
    if not body.get("messages"):
        raise Denied("messages is required", 400)
    check_rate(agent["id"])
    policy = await get_policy(agent["policy"])
    requested = body.get("model") or "auto"
    tier = difficulty(body) if requested == "auto" else None
    model = TIERS[tier] if tier else requested

    state = await budget_state(agent)
    if state == "over":
        if policy.on_budget_exceeded == "block":
            raise Denied("LLM budget exhausted", 402)
        tier, model = "easy", TIERS["easy"]

    rec = dict(agent_id=agent["id"], model_requested=requested, tier=tier, cache_hit=False,
               tokens_in=0, tokens_out=0, cost_usd=0.0)
    vec = None
    if cacheable(body):
        vec = await embed(_text(body))
        if hit := lookup(agent["id"], requested, vec):
            rec.update(model_used=hit.get("model"), cache_hit=True, latency_ms=(time.perf_counter() - t0) * 1000)
            await _log(agent, rec)
            return hit

    params = {k: v for k, v in body.items() if k in PASSTHROUGH}
    while True:
        try:
            resp = await litellm.acompletion(model=model, **params)
            break
        except Exception:
            if not tier or tier == "hard" or state == "over":
                raise
            tier = ORDER[ORDER.index(tier) + 1]  # retry one tier up
            model = TIERS[tier]

    try:
        cost = litellm.completion_cost(completion_response=resp)
    except Exception:
        cost = 0.0  # unknown model price
    out = resp.model_dump()
    usage = out.get("usage") or {}
    rec.update(model_used=model, tier=tier, tokens_in=usage.get("prompt_tokens", 0),
               tokens_out=usage.get("completion_tokens", 0), cost_usd=cost,
               latency_ms=(time.perf_counter() - t0) * 1000)
    await _log(agent, rec)
    if vec is not None:
        _cache[agent["id"]].append((requested, vec, out))
    return out


async def _log(agent, rec):
    LLM_CALLS.labels(agent["name"], rec["tier"] or "explicit", str(rec["cache_hit"])).inc()
    LLM_COST.labels(agent["name"]).inc(rec["cost_usd"])
    async with db.engine.begin() as c:
        await c.execute(insert(db.llm_calls).values(**rec))
