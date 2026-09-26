"""YAML policies: first matching rule wins, else `default`.

`when` is a small Python-syntax expression over `args`, checked against a node
whitelist at load time, e.g. `not endswith(args.to, '@mycompany.com')`.
"""
import ast
import fnmatch
import operator
import re
from dataclasses import dataclass, field

import yaml

ACTIONS = {"allow", "deny", "approve"}
_WRITE = re.compile(
    r"\b(insert|update|delete|drop|alter|create|truncate|grant|revoke|merge|copy|call|exec|execute"
    r"|attach|pragma|vacuum|lock|into|set)\b", re.I)


def sql_is_read_only(sql):
    # ponytail: keyword heuristic that errs toward "not read-only" (a literal containing 'delete'
    # is rejected); swap in a real parser (sqlglot) if false denials hurt.
    if not isinstance(sql, str):
        return False
    sql = re.sub(r"--[^\n]*|/\*.*?\*/", " ", sql, flags=re.S)
    stmts = [s.strip() for s in sql.split(";") if s.strip()]
    return bool(stmts) and not _WRITE.search(sql) and all(
        s.split()[0].lower() in ("select", "with", "show", "explain", "describe") for s in stmts)


FUNCS = {
    "sql_is_read_only": sql_is_read_only,
    "endswith": lambda s, x: isinstance(s, str) and s.lower().endswith(x.lower()),
    "startswith": lambda s, x: isinstance(s, str) and s.lower().startswith(x.lower()),
    "contains": lambda s, x: s is not None and x in s,
    "matches": lambda s, p: isinstance(s, str) and re.search(p, s) is not None,
    "len": lambda x: len(x) if x is not None else 0,
}
CMP = {ast.Eq: operator.eq, ast.NotEq: operator.ne, ast.Lt: operator.lt, ast.LtE: operator.le,
       ast.Gt: operator.gt, ast.GtE: operator.ge,
       ast.In: lambda a, b: a in b, ast.NotIn: lambda a, b: a not in b}
_OK = (ast.Expression, ast.BoolOp, ast.And, ast.Or, ast.UnaryOp, ast.Not, ast.Compare, ast.Call,
       ast.Name, ast.Attribute, ast.Subscript, ast.Constant, ast.List, ast.Tuple, ast.Load, *CMP)


def compile_when(src: str) -> ast.Expression:
    tree = ast.parse(src, mode="eval")
    for n in ast.walk(tree):
        if not isinstance(n, _OK):
            raise ValueError(f"unsupported syntax in {src!r}: {type(n).__name__}")
        if isinstance(n, ast.Name) and n.id != "args" and n.id not in FUNCS:
            raise ValueError(f"unknown name {n.id!r} in {src!r}")
        if isinstance(n, ast.Call) and (not isinstance(n.func, ast.Name) or n.keywords):
            raise ValueError(f"only plain calls to {sorted(FUNCS)} allowed in {src!r}")
    return tree


def _eval(n, args):
    match n:
        case ast.Expression(body=b):
            return _eval(b, args)
        case ast.BoolOp(op=ast.And(), values=vs):
            return all(_eval(v, args) for v in vs)
        case ast.BoolOp(op=ast.Or(), values=vs):
            return any(_eval(v, args) for v in vs)
        case ast.UnaryOp(operand=o):
            return not _eval(o, args)
        case ast.Compare(left=left, ops=ops, comparators=rights):
            a = _eval(left, args)
            for op, r in zip(ops, rights):
                b = _eval(r, args)
                if not CMP[type(op)](a, b):
                    return False
                a = b
            return True
        case ast.Call(func=ast.Name(id=f), args=a):
            return FUNCS[f](*[_eval(x, args) for x in a])
        case ast.Attribute(value=v, attr=k):
            base = _eval(v, args)
            return base.get(k) if isinstance(base, dict) else None
        case ast.Subscript(value=v, slice=s):
            base, k = _eval(v, args), _eval(s, args)
            return base.get(k) if isinstance(base, dict) else None
        case ast.Name(id="args"):
            return args
        case ast.Constant(value=v):
            return v
        case ast.List(elts=e) | ast.Tuple(elts=e):
            return [_eval(x, args) for x in e]
    raise ValueError(f"unsupported node {type(n).__name__}")


@dataclass
class Rule:
    tool: str
    action: str
    when: str | None = None
    expr: ast.Expression | None = field(default=None, repr=False)


@dataclass
class Policy:
    agent: str
    default: str = "deny"
    rules: list[Rule] = field(default_factory=list)
    on_injection: str = "block"  # block | strip | warn | approve
    injection_threshold: float = 0.8
    on_budget_exceeded: str = "block"  # block | downgrade
    on_secret: str = "block"  # block | approve | allow: secrets or card numbers in outgoing arguments
    on_prompt_injection: str = "allow"  # LLM path, content the app adds (RAG context, tool results): allow | warn | strip | block
    on_user_attack: str = "allow"  # LLM path, the end user's own latest message: allow | warn | strip | block
    max_user_warnings: int = 3  # blocked attacks from one end user (the request's `user` field) before lockout
    lockout_minutes: int = 15
    on_input_secret: str = "mask"  # secrets in messages are removed before the model sees them: mask | allow
    on_output_leak: str = "mask"  # LLM path, model answers containing secrets: mask | block | allow


def load_policy(src: str) -> Policy:
    d = yaml.safe_load(src)
    if not isinstance(d, dict) or "agent" not in d:
        raise ValueError("policy must be a mapping with an 'agent' key")
    rules = []
    for i, r in enumerate(d.get("rules") or []):
        if r.get("action") not in ACTIONS or not isinstance(r.get("tool"), str):
            raise ValueError(f"rules[{i}]: need 'tool' and action in {sorted(ACTIONS)}")
        when = r.get("when")
        rules.append(Rule(r["tool"], r["action"], when, compile_when(when) if when else None))
    p = Policy(agent=d["agent"], default=d.get("default", "deny"), rules=rules,
               on_injection=d.get("on_injection", "block"),
               injection_threshold=float(d.get("injection_threshold", 0.8)),
               on_budget_exceeded=d.get("on_budget_exceeded", "block"),
               on_secret=d.get("on_secret", "block"),
               on_prompt_injection=d.get("on_prompt_injection", "allow"),
               on_output_leak=d.get("on_output_leak", "mask"),
               on_user_attack=d.get("on_user_attack", "allow"),
               max_user_warnings=int(d.get("max_user_warnings", 3)),
               lockout_minutes=int(d.get("lockout_minutes", 15)),
               on_input_secret=d.get("on_input_secret", "mask"))
    if p.default not in ACTIONS or p.on_injection not in ("block", "strip", "warn", "approve") \
            or p.on_budget_exceeded not in ("block", "downgrade") or p.on_secret not in ("block", "approve", "allow") \
            or p.on_prompt_injection not in ("allow", "warn", "strip", "block") \
            or p.on_output_leak not in ("mask", "block", "allow") \
            or p.on_user_attack not in ("allow", "warn", "strip", "block") \
            or p.on_input_secret not in ("mask", "allow") or p.max_user_warnings < 1:
        raise ValueError("bad default / on_injection / on_budget_exceeded / on_secret / "
                         "on_prompt_injection / on_output_leak / on_user_attack / on_input_secret value")
    return p


def decide(p: Policy, tool: str, args: dict) -> tuple[str, str]:
    """-> (action, which rule decided). A condition that errors denies (fail closed)."""
    for i, r in enumerate(p.rules):
        if not fnmatch.fnmatchcase(tool, r.tool):
            continue
        label = f"rules[{i}] {r.tool}"
        if r.expr is not None:
            try:
                if not _eval(r.expr, args or {}):
                    continue
            except Exception as e:
                return "deny", f"{label} (condition error: {e})"
        return r.action, label
    return p.default, "default"


def visible(p: Policy, tool: str) -> bool:
    """False only if every path through the policy denies the tool: hide it from tools/list."""
    for r in p.rules:
        if fnmatch.fnmatchcase(tool, r.tool):
            if r.expr is None:
                return r.action != "deny"
            if r.action != "deny":
                return True
    return p.default != "deny"
