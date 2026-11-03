#!/usr/bin/env python3
"""Break the once-a-day rescan on purpose and prove tests/test_daily_rescan.py notices.

Each mutation is applied to both hand-maintained copies (azuredeploy.json and the standalone
playbook), so the drift check stays quiet and only the rescan test can catch it. A mutation
that survives is BLIND and the run exits non-zero.

    python3 tests/mutate_daily_rescan.py
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FILES = ["azuredeploy.json", os.path.join("Playbooks", "SOCRadar-Alarm-Import", "azuredeploy.json")]
TEST = os.path.join("tests", "test_daily_rescan.py")


def find(actions, name):
    for key, value in actions.items():
        if key == name:
            return value
        for sub in ("actions", "else"):
            if sub in value:
                inner = value[sub] if sub == "actions" else value[sub].get("actions", {})
                hit = find(inner, name)
                if hit is not None:
                    return hit
    return None


def import_actions(template):
    for resource in template["resources"]:
        if resource["type"] == "Microsoft.Logic/workflows":
            actions = resource["properties"]["definition"]["actions"]
            if "Determine_Lookback" in actions:
                return actions


def lookback(old, new):
    def edit(t):
        node = find(import_actions(t), "Determine_Lookback")
        assert old in node["inputs"], old
        node["inputs"] = node["inputs"].replace(old, new, 1)
    return edit


def drop_user_agent(t):
    del find(import_actions(t), "Get_SOCRadar_Page")["inputs"]["headers"]["User-Agent"]


def drop_backfill_user_agent(t):
    del find(import_actions(t), "Fetch_Backfill_Alarm")["inputs"]["headers"]["User-Agent"]


def rescan_parameter(t):
    t["parameters"]["RescanDays"] = {"type": "int", "defaultValue": 5}


def drop_truncated_gate(t):
    gate = find(import_actions(t), "Check_If_Should_Import")["expression"]["and"]
    gate[:] = [g for g in gate if "incidents_truncated" not in json.dumps(g)]


MUTATIONS = [
    ("the once-a-day guard removed (rescan on every run)",
     lookback("less(ticks(coalesce(body('Read_Checkpoint')?['LastRunUtc']", "greaterOrEquals(ticks(coalesce(body('Read_Checkpoint')?['LastRunUtc']")),
    ("the guard reads the checkpoint without a fallback",
     lookback("less(ticks(coalesce(body('Read_Checkpoint')?['LastRunUtc'], utcNow()))", "less(ticks(body('Read_Checkpoint')?['LastRunUtc'])")),
    ("the rescan window cut to 12 hours", lookback("7200", "720")),
    ("the rescan hour moved to 19:00", lookback("'T09:00:00Z'", "'T19:00:00Z'")),
    ("the rescan before 09:00 instead of after", lookback("and(greaterOrEquals(ticks(utcNow())", "and(less(ticks(utcNow())")),
    ("the 7-day clamp removed", lookback("10080", "100800")),
    ("the User-Agent dropped from the page call", drop_user_agent),
    ("the User-Agent dropped from the backfill call", drop_backfill_user_agent),
    ("a parameter that exposes the rescan", rescan_parameter),
    ("Direct mode imports while the existing-incident list is cut short", drop_truncated_gate),
]


def run(workdir):
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    done = subprocess.run([sys.executable, TEST], cwd=workdir, env=env, capture_output=True, text=True)
    # exit 1 alone also means a traceback; only the test's own failure banner counts as caught
    return 1 if done.returncode == 1 and "DAILY RESCAN CHECK FAILED" in done.stdout else (2 if done.returncode else 0)


blind = []
for label, edit in MUTATIONS:
    work = tempfile.mkdtemp(prefix="mutate-rescan-")
    try:
        os.makedirs(os.path.join(work, "tests"))
        shutil.copy(os.path.join(REPO, TEST), os.path.join(work, TEST))
        for rel in FILES:
            dest = os.path.join(work, rel)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(os.path.join(REPO, rel), encoding="utf-8") as fh:
                template = json.load(fh)
            edit(template)
            with open(dest, "w", encoding="utf-8") as fh:
                json.dump(template, fh, indent=4)
        code = run(work)
        verdict = "caught" if code == 1 else ("CRASH" if code else "BLIND")
        print(f"  {verdict:7} {label}")
        if verdict != "caught":
            blind.append(label)
    finally:
        shutil.rmtree(work, ignore_errors=True)

if blind:
    print(f"\n{len(blind)} mutation(s) blind or crashed.")
    sys.exit(1)
print(f"\nall {len(MUTATIONS)} mutation(s) caught, blind 0")
