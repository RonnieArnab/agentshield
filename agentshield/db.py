import datetime as dt
import os

from sqlalchemy import JSON, Boolean, Column, DateTime, Float, Integer, MetaData, String, Table, Text, text
from sqlalchemy.ext.asyncio import create_async_engine

URL = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///agentshield.db")
if URL.startswith(("postgres://", "postgresql://")):  # hosted providers hand out driver-less URLs
    URL = "postgresql+asyncpg://" + URL.split("://", 1)[1]
engine = create_async_engine(URL)
md = MetaData()


def now():
    return dt.datetime.now(dt.UTC)


def _id():
    return Column("id", Integer, primary_key=True)


def _created():
    return Column("created_at", DateTime(timezone=True), default=now, index=True)


agents = Table(
    "agents", md, _id(),
    Column("name", String, unique=True, nullable=False),
    Column("api_key_hash", String, unique=True, nullable=False),
    Column("policy", String, nullable=False),
    Column("daily_budget_usd", Float, default=5.0),
    Column("monthly_budget_usd", Float, default=100.0),
)

policies = Table(
    "policies", md, _id(),
    Column("name", String, index=True, nullable=False),
    Column("yaml_source", Text, nullable=False),
    Column("version", Integer, nullable=False),
    _created(),
)

tool_calls = Table(
    "tool_calls", md, _id(),
    Column("agent_id", Integer, index=True),
    Column("server", String),
    Column("tool", String),
    Column("args_json", JSON),  # masked before insert
    Column("decision", String),  # allow | warn | deny | error
    Column("rule_matched", String),
    Column("reason", Text),
    Column("injection_score", Float),
    Column("response_hash", String),
    Column("approval_id", Integer),
    Column("latency_ms", Float),
    Column("overhead_ms", Float),  # latency minus upstream tool time and human wait
    _created(),
)

llm_calls = Table(
    "llm_calls", md, _id(),
    Column("agent_id", Integer, index=True),
    Column("model_requested", String),
    Column("model_used", String),
    Column("tier", String),
    Column("cache_hit", Boolean),
    Column("tokens_in", Integer),
    Column("tokens_out", Integer),
    Column("cost_usd", Float),
    Column("latency_ms", Float),
    _created(),
)

approvals = Table(
    "approvals", md, _id(),
    Column("agent_id", Integer, index=True),
    Column("tool", String),
    Column("args_json", JSON),
    Column("reason", Text),
    Column("status", String, index=True),  # pending | approved | rejected | timeout
    Column("reviewer", String),
    Column("requested_at", DateTime(timezone=True), default=now),
    Column("decided_at", DateTime(timezone=True)),
)

alerts = Table(
    "alerts", md, _id(),
    Column("agent_id", Integer, index=True),
    Column("kind", String),  # new_tool | deny_spike
    Column("detail", Text),
    _created(),
)


async def init():
    async with engine.begin() as c:
        await c.run_sync(md.create_all)
        if c.dialect.name == "postgresql":  # audit tables are append-only at the DB level
            for t in ("tool_calls", "llm_calls"):
                for op in ("UPDATE", "DELETE"):
                    await c.execute(text(f"CREATE OR REPLACE RULE {t}_no_{op.lower()} AS ON {op} TO {t} DO INSTEAD NOTHING"))
