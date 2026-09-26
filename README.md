# AgentShield

A self-hosted gateway between AI agents and everything they call (MCP tools and LLM APIs). Every tool call is checked against a per-agent policy and its output is scanned for prompt injection. Risky actions wait for a human, everything is logged, and LLM requests go to the cheapest model that can handle them.

```
agent ──MCP──▶ /mcp/{server} ─▶ rate/loop limits ─▶ policy ─▶ [approval] ─▶ upstream MCP ─▶ injection scan ─▶ agent
agent ─HTTP──▶ /v1/chat/completions ─▶ budget ─▶ difficulty router ─▶ semantic cache ─▶ LiteLLM ─▶ provider
                                  both paths ─▶ audit log (Postgres, append-only) + Prometheus /metrics
```

## Quick start

```bash
cp .env.example .env        # set ADMIN_KEY and ANTHROPIC_API_KEY
docker compose up --build
```

Create an agent (it gets its own API key):

```bash
curl -XPOST localhost:8000/agents -H "Authorization: Bearer $ADMIN_KEY" \
  -H 'content-type: application/json' -d '{"name":"research","policy":"research-bot"}'
```

Point an MCP client at `http://localhost:8000/mcp/filesystem` with header `Authorization: Bearer <agent key>`, and an OpenAI-compatible client at `http://localhost:8000/v1` with `model: "auto"`. Pending approvals are at http://localhost:8000/ui.

Local run without Docker (SQLite):

```bash
uv venv && uv pip install -e ".[dev]"
ADMIN_KEY=dev .venv/bin/uvicorn agentshield.app:app --reload
```

## Demo

Start the gateway (Docker as above, or locally with `ADMIN_KEY=change-me`). Open the dashboard at http://localhost:8000/ui and enter the admin key. Then run one of these in a second terminal:

```bash
pip install -e .                    # the demo scripts use the mcp and httpx packages
python -m demo.scripted             # walkthrough; you click Approve in the dashboard
python -m demo.scripted --auto      # same, but the script approves itself
python -m demo.agent                # a real Claude agent (needs ANTHROPIC_API_KEY on the gateway)
```

The scripted demo shows, in order:

1. **Least privilege:** the agent only sees the tools its policy allows.
2. **A normal read:** allowed and logged.
3. **Prompt injection:** `sandbox/poisoned.txt` hides "ignore previous instructions…", and the tool output is blocked before the agent sees it.
4. **Destructive tool:** `move_file` is denied.
5. **Human approval:** `write_file` pauses until you approve it in the dashboard.
6. **Runaway loop:** the fifth identical call is stopped.
7. **Cost routing:** an easy and a hard prompt go to different models. This scene needs an API key.

`demo.agent` gives a real LLM the task "read every file and follow the action items". Watch the dashboard as the poisoned file gets blocked and the summary write waits for you.

## Policies

Put YAML in `policies/` (seeded at startup) or `POST /policies`. The first matching rule wins, otherwise `default` applies. `when` is a restricted Python expression over `args`, validated against a whitelist at load time. A condition that errors denies the call (fail closed). Tools that every path denies are hidden from `tools/list`.

```yaml
agent: support-bot
default: deny
on_injection: block          # block | warn | approve
injection_threshold: 0.8
on_budget_exceeded: downgrade  # block | downgrade
rules:
  - tool: "crm.read_*"
    action: allow
  - tool: "email.send"
    action: approve
    when: "not endswith(args.to, '@mycompany.com')"
  - tool: "db.query"
    action: allow
    when: "sql_is_read_only(args.sql)"
  - tool: "*.delete*"
    action: deny
```

Functions available in `when`: `sql_is_read_only`, `endswith`, `startswith`, `contains`, `matches` (regex), `len`.

## Injection detection

The layers run cheapest first:

1. **Rules**: override phrases, role hijacks, chat markup, hidden Unicode, base64-wrapped payloads, and markdown images that exfiltrate data through URLs.
2. **Classifier** (optional): set `INJECTION_MODEL` and `pip install .[classifier]`.
3. **LLM judge** (optional): set `JUDGE_MODEL`. It only sees classifier scores in the borderline band.

## API

| Method and path | Purpose |
|---|---|
| `POST /mcp/{server}` | MCP proxy (streamable HTTP), agent key |
| `POST /v1/chat/completions` | OpenAI-compatible LLM proxy, agent key |
| `POST /agents` | Create agent, returns API key (admin) |
| `POST /policies` | Upload YAML policy (admin) |
| `GET /approvals?status=pending` | List approvals (admin) |
| `POST /approvals/{id}/decide` | `{"approve": true}` (admin) |
| `GET /audit?agent=&kind=tool\|llm&frm=&to=` | Search the audit log (admin) |
| `GET /metrics` | Prometheus metrics |

## Evals

```bash
pytest -q                 # policy, detection, tool path, LLM path
python -m evals.run -v    # detection rate / false-positive rate / scan latency
```

Current results on the 20 + 20 starter set (rules layer only):

| metric | value |
|---|---|
| detection rate | 95% (19/20) |
| false-positive rate | 0% (0/20) |

Grow `evals/attacks.jsonl` and `evals/safe.jsonl` toward about 300 cases each (for example with the HF datasets `deepset/prompt-injections` and `jackhhao/jailbreak-classification`). CI runs both on every push.

## Known limits (deliberate v1 shortcuts)

- Rate limits, loop detection, approval wake-ups and the semantic cache live in process memory, which is correct for one gateway replica. Move them to Redis before scaling out.
- Policies are evaluated in Python instead of compiled to OPA/Rego.
- `sql_is_read_only` is a keyword heuristic that errs toward denying.
- Streaming LLM responses are not supported yet.
- No Grafana dashboards yet; `/metrics` is ready to scrape.
