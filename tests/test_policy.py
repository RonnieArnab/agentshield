import pathlib

import pytest

from agentshield.policy import decide, load_policy, sql_is_read_only, visible

P = load_policy(pathlib.Path("policies/support-bot.yaml").read_text())


@pytest.mark.parametrize("tool,args,want", [
    ("crm.read_contact", {"id": 1}, "allow"),
    ("email.send", {"to": "bob@mycompany.com"}, "allow"),
    ("email.send", {"to": "x@evil.com"}, "approve"),
    ("email.send", {}, "approve"),  # missing arg -> external path
    ("db.query", {"sql": "select * from users"}, "allow"),
    ("db.query", {"sql": "DELETE FROM users"}, "deny"),
    ("files.delete_file", {}, "deny"),
    ("shell.run", {}, "deny"),  # default
])
def test_decide(tool, args, want):
    assert decide(P, tool, args)[0] == want


@pytest.mark.parametrize("sql,ok", [
    ("SELECT 1", True),
    ("with t as (select 1) select * from t", True),
    ("-- comment\nselect a from b;", True),
    ("select 1; drop table users", False),
    ("WITH x AS (DELETE FROM t RETURNING *) SELECT * FROM x", False),
    ("select * into backup from users", False),
    ("update users set a=1", False),
    ("", False),
    (None, False),
])
def test_sql_read_only(sql, ok):
    assert sql_is_read_only(sql) is ok


def test_visible_hides_denied_tools():
    assert visible(P, "crm.read_x") and visible(P, "email.send")
    assert not visible(P, "files.delete_file") and not visible(P, "shell.run")


def test_condition_error_fails_closed():
    p = load_policy("agent: t\ndefault: allow\nrules:\n  - tool: x\n    action: allow\n    when: 'args.n > 3'\n")
    assert decide(p, "x", {"n": "abc"})[0] == "deny"


@pytest.mark.parametrize("bad", [
    "agent: t\nrules:\n  - tool: x\n    action: allow\n    when: \"__import__('os')\"\n",
    "agent: t\nrules:\n  - tool: x\n    action: allow\n    when: \"args.__class__()\"\n",
    "agent: t\nrules:\n  - tool: x\n    action: maybe\n",
    "agent: t\ndefault: sometimes\n",
])
def test_rejects_bad_policies(bad):
    with pytest.raises(ValueError):
        load_policy(bad)
