"""Short-lived shared state: Redis when REDIS_URL is set (safe for many gateway replicas),
process memory otherwise (one replica, zero setup)."""
import array
import hashlib
import json
import os
import time
from collections import defaultdict, deque

REDIS_URL = os.getenv("REDIS_URL")
r = None
if REDIS_URL:
    import redis.asyncio as aioredis

    r = aioredis.from_url(REDIS_URL)

_mem_hits: dict[str, deque] = defaultdict(deque)
_mem_lists: dict[str, deque] = {}
_mem_once: dict[str, float] = {}


async def over_rate(key: str, limit: int) -> bool:
    """Count one hit; True if `key` exceeded `limit` hits in the current minute."""
    if r:
        k = f"as:rate:{key}:{int(time.time() // 60)}"  # fixed one-minute window
        n = await r.incr(k)
        if n == 1:
            await r.expire(k, 120)
        return n > limit
    q, t = _mem_hits[key], time.monotonic()
    while q and t - q[0] > 60:
        q.popleft()
    if len(q) >= limit:
        return True
    q.append(t)
    return False


async def all_same(key: str, item: str, n: int) -> bool:
    """Append `item` to a list capped at n; True if the list is full and every entry is identical."""
    if r:
        k = f"as:last:{key}"
        async with r.pipeline() as p:
            items = (await p.lpush(k, item).ltrim(k, 0, n - 1).expire(k, 3600).lrange(k, 0, -1).execute())[-1]
        return len(items) == n and len(set(items)) == 1
    q = _mem_lists.setdefault(key, deque(maxlen=n))
    q.append(item)
    return len(q) == n and len(set(q)) == 1


async def once(key: str, ttl: int) -> bool:
    """True the first time `key` is seen within `ttl` seconds (for alert de-duplication)."""
    if r:
        return bool(await r.set(f"as:once:{key}", 1, nx=True, ex=ttl))
    now = time.time()
    if _mem_once.get(key, 0) > now:
        return False
    _mem_once[key] = now + ttl
    return True


# ---- semantic cache ----------------------------------------------------------------------
_mem_cache: dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
_index_ready = False
CACHE_TTL = int(os.getenv("CACHE_TTL_S", 86400))


def _tag(s: str) -> str:
    return hashlib.sha1(s.encode()).hexdigest()[:16]  # TAG-safe (no punctuation to escape)


_search = True  # False once we learn this Redis has no vector search (plain Redis, most managed tiers)


def _no_search(e: Exception) -> bool:
    global _search
    if "unknown command" in str(e).lower():
        _search = False
        return True
    return False


async def cache_get(agent_id: int, model: str, vec: list[float], min_sim: float):
    if not r or not _search:
        # ponytail: brute-force cosine over the last 1000 entries per agent, in-process only
        best, hit = min_sim, None
        for v, resp in _mem_cache[f"{agent_id}:{model}"]:
            if (s := sum(a * b for a, b in zip(vec, v))) >= best:
                best, hit = s, resp
        return hit
    from redis.commands.search.query import Query

    q = (Query(f"(@agent:{{{agent_id}}} @model:{{{_tag(model)}}})=>[KNN 1 @vec $v AS dist]")
         .return_fields("resp", "dist").dialect(2))
    try:
        res = await r.ft("as-cache").search(q, query_params={"v": array.array("f", vec).tobytes()})
    except Exception as e:  # index not created yet (nothing cached), or no vector search at all
        if "no such index" in str(e).lower() or "unknown index" in str(e).lower() or _no_search(e):
            return await cache_get(agent_id, model, vec, min_sim) if not _search else None
        raise
    if res.docs and 1 - float(res.docs[0].dist) >= min_sim:  # cosine distance -> similarity
        return json.loads(res.docs[0].resp)
    return None


async def cache_put(agent_id: int, model: str, vec: list[float], resp: dict):
    global _index_ready
    if not r or not _search:
        _mem_cache[f"{agent_id}:{model}"].append((vec, resp))
        return
    if not _index_ready:
        from redis.commands.search.field import TagField, TextField, VectorField
        from redis.commands.search.index_definition import IndexDefinition, IndexType

        try:
            await r.ft("as-cache").create_index(
                [TagField("agent"), TagField("model"), TextField("resp"),
                 VectorField("vec", "HNSW", {"TYPE": "FLOAT32", "DIM": len(vec), "DISTANCE_METRIC": "COSINE"})],
                definition=IndexDefinition(prefix=["as:cache:"], index_type=IndexType.HASH))
        except Exception as e:  # already exists (another replica, or a restart)
            if _no_search(e):
                return await cache_put(agent_id, model, vec, resp)
            if "exists" not in str(e).lower():
                raise
        _index_ready = True
    k = f"as:cache:{agent_id}:{time.time_ns()}"
    await r.hset(k, mapping={"agent": str(agent_id), "model": _tag(model), "resp": json.dumps(resp),
                             "vec": array.array("f", vec).tobytes()})
    await r.expire(k, CACHE_TTL)
