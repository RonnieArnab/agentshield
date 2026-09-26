"""A fake office backend as an MCP server: an inbox, outgoing email, and a customer database.
Deliberately unsafe on its own (query_db runs any SQL); the gateway's policies are what protect it.
State lives in OFFICE_DIR so demos and benchmarks can seed it and inspect the result."""
import json
import os
import pathlib
import sqlite3

from mcp.server.mcpserver import MCPServer

DIR = pathlib.Path(os.getenv("OFFICE_DIR", "sandbox/office"))
CUSTOMERS = [("Acme Corp", "ops@acme.example", "pro", 1200), ("Globex", "it@globex.example", "free", 0),
             ("Initech", "admin@initech.example", "pro", 950), ("Umbrella", "sec@umbrella.example", "free", 0),
             ("Hooli", "billing@hooli.example", "enterprise", 5400)]
INBOX = [{"from": "alice@mycompany.com", "subject": "Offsite", "body": "The offsite moved to Thursday, room 4B."},
         {"from": "billing@vendor.example", "subject": "Invoice 2231", "body": "Invoice 2231 for $120 is due Friday."}]


def seed(extra_inbox: list[dict] | None = None, directory: pathlib.Path = DIR):
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "inbox.json").write_text(json.dumps(INBOX + (extra_inbox or []), indent=1))
    (directory / "outbox.jsonl").write_text("")
    db = directory / "company.db"
    db.unlink(missing_ok=True)
    with sqlite3.connect(db) as c:
        c.execute("CREATE TABLE customers (id INTEGER PRIMARY KEY, name TEXT, email TEXT, plan TEXT, mrr INTEGER)")
        c.executemany("INSERT INTO customers (name, email, plan, mrr) VALUES (?, ?, ?, ?)", CUSTOMERS)


def outbox(directory: pathlib.Path = DIR) -> list[dict]:
    p = directory / "outbox.jsonl"
    return [json.loads(line) for line in p.read_text().splitlines() if line.strip()] if p.exists() else []


def customer_count(directory: pathlib.Path = DIR) -> int:
    with sqlite3.connect(directory / "company.db") as c:
        return c.execute("SELECT count(*) FROM customers").fetchone()[0]


mcp = MCPServer("office")


@mcp.tool()
def read_inbox() -> str:
    """Read all emails in the user's inbox."""
    if not (DIR / "inbox.json").exists():
        seed()
    mails = json.loads((DIR / "inbox.json").read_text())
    return "\n\n".join(f"From: {m['from']}\nSubject: {m['subject']}\n\n{m['body']}" for m in mails)


@mcp.tool()
def send_email(to: str, subject: str, body: str) -> str:
    """Send an email."""
    with (DIR / "outbox.jsonl").open("a") as f:
        f.write(json.dumps({"to": to, "subject": subject, "body": body}) + "\n")
    return f"Email sent to {to}."


@mcp.tool()
def query_db(sql: str) -> str:
    """Run a SQL query against the company database (table: customers(id, name, email, plan, mrr))."""
    if not (DIR / "company.db").exists():
        seed()
    with sqlite3.connect(DIR / "company.db") as c:
        cur = c.execute(sql)
        rows = cur.fetchall()
        return json.dumps(rows) if cur.description else f"{cur.rowcount} row(s) affected."


if __name__ == "__main__":
    mcp.run()
