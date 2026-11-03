#!/usr/bin/env python3
"""The import looks five days back once a day, after 09:00 UTC, with no switch for it.

The window comes from the Determine_Lookback expression. This file evaluates the expression
that is shipped in the root template and in the standalone playbook (a small evaluator for the
dozen Workflow Definition functions it uses) against fixed clock times, so the rule is tested
as written and not as remembered:

  - no checkpoint                      -> InitialLookbackMinutes, no rescan
  - first run at or after 09:00 UTC    -> at least 7200 minutes (5 days), once per UTC day
  - every other run                    -> the gap since the last run, as before
  - a stale checkpoint                 -> still clamped to 10080 minutes (7 days)

It also checks that Direct mode stops importing while the list of existing incidents is cut short
(the longer window would otherwise import twice), that no parameter exposes the rescan, and that every call to SOCRadar names this
integration in the User-Agent header.

Run:  python3 tests/test_daily_rescan.py
"""

import glob
import json
import os
import re
import sys
from datetime import datetime, timedelta

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FILES = [os.path.join(REPO, "azuredeploy.json")] + sorted(
    glob.glob(os.path.join(REPO, "Playbooks", "SOCRadar-Alarm-Import", "azuredeploy.json")))
USER_AGENT = "SOCRadar-Azure-Sentinel-Incidents-Import"

failures = []


def check(condition, message):
    if not condition:
        failures.append(message)


def rel(path):
    return os.path.relpath(path, REPO)


def ticks(value):
    dt = value if isinstance(value, datetime) else datetime.strptime(
        re.sub(r"(\.\d{6})\d*Z$", r"\1Z", value if "." in value else value.replace("Z", ".000000Z")),
        "%Y-%m-%dT%H:%M:%S.%fZ")
    delta = dt - datetime(1, 1, 1)
    return delta.days * 864_000_000_000 + delta.seconds * 10_000_000 + delta.microseconds * 10


# ---- a small evaluator for the expression, nothing more --------------------------------

TOKEN = re.compile(r"\s*(?:(?P<str>'(?:[^']|'')*')|(?P<num>\d+)|(?P<name>[A-Za-z_]\w*)|(?P<op>\?\[|[(),\]]))")


def tokenize(text):
    pos, out = 0, []
    while pos < len(text):
        m = TOKEN.match(text, pos)
        if not m:
            raise ValueError(f"cannot read the expression at: {text[pos:pos + 30]!r}")
        pos = m.end()
        kind = m.lastgroup
        out.append((kind, m.group(kind)))
    return out


def evaluate(expression, now, checkpoint, params):
    toks = tokenize(expression.lstrip("@"))
    idx = [0]

    def peek():
        return toks[idx[0]] if idx[0] < len(toks) else (None, None)

    def take():
        idx[0] += 1
        return toks[idx[0] - 1]

    def expr():
        """Parse one expression into a thunk, so `if` can leave its other branch unevaluated."""
        kind, val = take()
        if kind == "str":
            text = val[1:-1].replace("''", "'")
            return lambda: text
        if kind == "num":
            return lambda: int(val)
        assert kind == "name", (kind, val)
        take()  # (
        args = []
        if peek() != ("op", ")"):
            while True:
                args.append(expr())
                if peek() == ("op", ","):
                    take()
                    continue
                break
        take()  # )
        node = (lambda: call_if(args)) if val == "if" else (lambda: call(val, [a() for a in args]))
        while peek() == ("op", "?["):
            take()
            key = expr()
            take()  # ]
            node = (lambda inner, k: lambda: (inner() or {}).get(k()) if isinstance(inner(), dict) else None)(node, key)
        return node

    def call_if(args):
        return args[1]() if args[0]() else args[2]()

    def fmt(dt, pattern):
        assert pattern == "yyyy-MM-dd", pattern
        return dt.strftime("%Y-%m-%d")

    def call(name, a):
        table = {
            "utcNow": lambda: now,
            "body": lambda n: checkpoint if n == "Read_Checkpoint" else {},
            "parameters": lambda n: params[n],
            "coalesce": lambda *xs: next((x for x in xs if x is not None), None),
            "empty": lambda x: x in (None, "", {}, []),
            "min": lambda *xs: min(xs), "max": lambda *xs: max(xs),
            "add": lambda x, y: x + y, "sub": lambda x, y: x - y,
            "mul": lambda x, y: x * y, "div": lambda x, y: x // y,
            "ticks": ticks,
            "concat": lambda *xs: "".join(str(x) for x in xs),
            "formatDateTime": fmt,
            "and": lambda *xs: all(xs),
            "greaterOrEquals": lambda x, y: x >= y,
            "less": lambda x, y: x < y,
        }
        return table[name](*a)

    root = expr()
    assert idx[0] == len(toks), "trailing tokens"
    return root()


def is_import_app(resource):
    """The root template also carries the Sync Logic App, which has no window and is not tested here."""
    return (resource.get("type") == "Microsoft.Logic/workflows"
            and "Determine_Lookback" in resource["properties"]["definition"]["actions"])


def lookback_expression(path):
    with open(path, encoding="utf-8") as fh:
        template = json.load(fh)
    for resource in template["resources"]:
        if is_import_app(resource):
            return template, resource["properties"]["definition"]["actions"]["Determine_Lookback"]["inputs"]
    raise SystemExit(f"{rel(path)}: no Logic App")


def day(h, m, s=0, back=0):
    return datetime(2026, 10, 18, h, m, s) - timedelta(days=back)


def stamp(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + "0000000Z"


EXPECTED_GATE = {"and": [
    {"or": [{"equals": ["@parameters('ImportAllStatuses')", True]},
            {"equals": ["@coalesce(items('For_Each_Alarm')?['status'], 'OPEN')", "OPEN"]}]},
    {"equals": ["@parameters('IncidentMode')", "Direct"]},
    {"equals": ["@variables('incidents_truncated')", False]},
]}

PARAMS = {"InitialLookbackMinutes": 600, "PollingIntervalMinutes": 5}
SLOW = {"InitialLookbackMinutes": 600, "PollingIntervalMinutes": 15}

# (label, now, LastRunUtc or None, expected minutes)
CASES = [
    ("no checkpoint falls back, no rescan", day(9, 0, 30), None, 600),
    ("first run after 09:00 reaches back 5 days", day(9, 0, 30), stamp(day(8, 58)), 7200),
    ("later run the same day is a normal run", day(9, 5), stamp(day(9, 0, 30)), 60),
    ("before 09:00 it is a normal run", day(8, 59), stamp(day(9, 3, back=1)), 1451),
    ("a run stamped exactly 09:00:00 does not repeat the rescan", day(9, 5), stamp(day(9, 0, 0)), 60),
    ("one second before 09:00 the next run rescans", day(9, 0, 10), stamp(day(8, 59, 59)), 7200),
    ("a missed morning is made up at the next run", day(12, 0), stamp(day(8, 0)), 7200),
    ("a three-day-old checkpoint rescans 5 days, not 3", day(12, 0), stamp(day(12, 0, back=3)), 7200),
    ("an eight-day-old checkpoint is clamped to 7 days", day(12, 0), stamp(day(12, 0, back=8)), 10080),
    ("a normal run keeps the gap plus 15 minutes", day(15, 0), stamp(day(10, 0)), 315),
    ("an empty checkpoint value counts as no checkpoint", day(9, 0, 30), "", 600),
]
# At a 15 minute interval the floor is six intervals (90), not 60 or 15.
CASES_SLOW = [
    ("slow polling: a normal run keeps the six-interval floor", day(15, 5), stamp(day(15, 0)), 90),
    ("slow polling: the rescan still reaches back 5 days", day(9, 10), stamp(day(8, 55)), 7200),
]

for path in FILES:
    template, expression = lookback_expression(path)
    for label, now, last, expected in CASES:
        got = evaluate(expression, now, {"LastRunUtc": last} if last else {}, PARAMS)
        check(got == expected, f"{rel(path)}: {label}: expected {expected}, got {got}")

    check("less(ticks(coalesce(body('Read_Checkpoint')?['LastRunUtc'], utcNow())), ticks(concat(" in expression,
          f"{rel(path)}: the once-a-day guard reads the checkpoint without a fallback")
    gate = None
    for resource in template["resources"]:
        if is_import_app(resource):
            loop = resource["properties"]["definition"]["actions"]["Pagination_Loop"]["actions"]
            gate = loop["For_Each_Alarm"]["actions"]["Check_If_Should_Import"].get("expression")
    check(gate == EXPECTED_GATE,
          f"{rel(path)}: Check_If_Should_Import is not the expected gate (open alarms or ImportAllStatuses, "
          f"Direct mode, list of existing incidents complete): {json.dumps(gate)[:200]}")

    for label, now, last, expected in CASES_SLOW:
        got = evaluate(expression, now, {"LastRunUtc": last} if last else {}, SLOW)
        check(got == expected, f"{rel(path)}: {label}: expected {expected}, got {got}")

    names = " ".join(template.get("parameters", {})).lower()
    check("rescan" not in names, f"{rel(path)}: a parameter exposes the rescan")

    calls = 0
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    for resource in template["resources"]:
        if not is_import_app(resource):
            continue

        def walk(actions):
            global calls
            for name, body in (actions or {}).items():
                inputs = body.get("inputs") if isinstance(body.get("inputs"), dict) else {}
                if "platform.socradar.com" in str(inputs.get("uri", "")):
                    calls += 1
                    agent = (inputs.get("headers") or {}).get("User-Agent", "")
                    check(agent.startswith(USER_AGENT), f"{rel(path)}: {name} sends no User-Agent that names this integration")
                walk(body.get("actions"))
                for key in ("else", "default"):
                    if isinstance(body.get(key), dict):
                        walk(body[key].get("actions"))
                for case in (body.get("cases") or {}).values():
                    walk(case.get("actions"))

        walk(resource["properties"]["definition"]["actions"])
    check(calls == 2, f"{rel(path)}: expected 2 calls to SOCRadar, found {calls}")

if failures:
    print("DAILY RESCAN CHECK FAILED\n")
    for item in failures:
        print("  - " + item)
    print(f"\n{len(failures)} problem(s).")
    sys.exit(1)

print(f"Daily rescan: {len(CASES)} clock cases in {len(FILES)} template(s), no parameter for it, "
      f"User-Agent on every SOCRadar call.")
