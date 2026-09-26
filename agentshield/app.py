import datetime as dt
import hmac
import logging
import os
import pathlib
from contextlib import AsyncExitStack, asynccontextmanager

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from pydantic import BaseModel
from sqlalchemy import select

from . import db, gateway, llm
from .gateway import Denied
from .mcp_proxy import mount_all

logging.basicConfig(level=logging.INFO)
ADMIN_KEY = os.getenv("ADMIN_KEY", "")
CONFIG = os.getenv("AGENTSHIELD_CONFIG", "config.yaml")
POLICY_DIR = pathlib.Path(os.getenv("POLICY_DIR", "policies"))


@asynccontextmanager
async def lifespan(app: FastAPI):
    if not ADMIN_KEY:
        raise RuntimeError("set ADMIN_KEY")
    await db.init()
    for f in sorted(POLICY_DIR.glob("*.yaml")):  # seed policies from disk
        await gateway.save_policy(f.read_text())
    async with AsyncExitStack() as stack:
        if pathlib.Path(CONFIG).exists():
            logging.info("MCP servers: %s", await mount_all(app, stack, CONFIG))
        yield


app = FastAPI(title="AgentShield", lifespan=lifespan)


@app.get("/metrics")
def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.exception_handler(Denied)
async def denied(_, e: Denied):
    return JSONResponse({"error": str(e)}, status_code=e.status)


def admin(authorization: str = Header("")):
    if not hmac.compare_digest(authorization.removeprefix("Bearer ").encode(), ADMIN_KEY.encode()):
        raise HTTPException(401, "admin key required")


async def agent(authorization: str = Header("")) -> dict:
    return await gateway.auth(authorization)


@app.post("/v1/chat/completions")
async def chat(body: dict, a: dict = Depends(agent)):
    try:
        return await llm.chat(a, body)
    except Denied:
        raise
    except Exception as e:  # provider / LiteLLM errors: missing key, unknown model, upstream outage
        raise HTTPException(502, f"LLM provider error: {e}"[:500])


class NewAgent(BaseModel):
    name: str
    policy: str
    daily_budget_usd: float = 5.0
    monthly_budget_usd: float = 100.0


@app.post("/agents", dependencies=[Depends(admin)])
async def create_agent(b: NewAgent):
    await gateway.get_policy(b.policy)  # must exist
    key = await gateway.create_agent(b.name, b.policy, b.daily_budget_usd, b.monthly_budget_usd)
    return {"name": b.name, "api_key": key}


@app.post("/policies", dependencies=[Depends(admin)])
async def upload_policy(request: Request):
    try:
        return await gateway.save_policy((await request.body()).decode())
    except ValueError as e:
        raise HTTPException(422, str(e))


@app.get("/approvals", dependencies=[Depends(admin)])
async def list_approvals(status: str = "pending"):
    async with db.engine.connect() as c:
        rows = await c.execute(select(db.approvals, db.agents.c.name.label("agent"))
                               .join(db.agents, db.agents.c.id == db.approvals.c.agent_id)
                               .where(db.approvals.c.status == status).order_by(db.approvals.c.id))
    return [r._asdict() for r in rows]


class Decision(BaseModel):
    approve: bool
    reviewer: str = "admin"


@app.post("/approvals/{aid}/decide", dependencies=[Depends(admin)])
async def decide(aid: int, d: Decision):
    if not await gateway.decide_approval(aid, d.approve, d.reviewer):
        raise HTTPException(409, "approval is not pending")
    return {"id": aid, "status": "approved" if d.approve else "rejected"}


@app.get("/audit", dependencies=[Depends(admin)])
async def audit(agent: str | None = None, kind: str = "tool", frm: dt.datetime | None = None, to: dt.datetime | None = None,
                limit: int = 100):
    t = db.tool_calls if kind == "tool" else db.llm_calls
    q = select(t, db.agents.c.name.label("agent")).join(db.agents, db.agents.c.id == t.c.agent_id)
    if agent:
        q = q.where(db.agents.c.name == agent)
    if frm:
        q = q.where(t.c.created_at >= frm)
    if to:
        q = q.where(t.c.created_at <= to)
    async with db.engine.connect() as c:
        rows = await c.execute(q.order_by(t.c.id.desc()).limit(min(limit, 1000)))
    return [r._asdict() for r in rows]


@app.get("/ui")
async def ui():
    return FileResponse(pathlib.Path(__file__).with_name("ui.html"))
