#!/usr/bin/env python3
"""Pin the four silent-loss guards added in task_azure_0056.

An 11-agent pre-delivery audit found four ways this import could lose alarms or create
duplicates while every log line still said the run succeeded. Each is now guarded, and
each guard is pinned here so a later edit cannot quietly take it away.

  S2  Pagination_Loop_Incidents is an Until with a limit. If it stops on the limit rather
      than an empty nextLink, the existing-incident list is partial and the run re-creates
      incidents that already exist.
  S3  coalesce(is_success, true) turned an unexpected 200 body into a successful empty
      page: the loop ended, the checkpoint advanced, and the alarms in that window were
      never read. A body that does not say success is not success.
  S4  The backfill read the alarm id with last(split(title, '#')), which picks the wrong
      segment as soon as the alarm's own title contains a '#'. The other reader already
      used [1].
  S5  Sync's status write had no else branch, so a refusal from SOCRadar left no trace.

Run:  python3 tests/test_import_integrity.py
"""

import json
import os

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT = os.path.join(REPO, "azuredeploy.json")
IMPORT = os.path.join(REPO, "Playbooks", "SOCRadar-Alarm-Import", "azuredeploy.json")
SYNC = os.path.join(REPO, "Playbooks", "SOCRadar-Alarm-Sync", "azuredeploy.json")

failures = []
checks = 0


def check(condition, message):
    global checks
    checks += 1
    if not condition:
        failures.append(message)


def rel(path):
    return os.path.relpath(path, REPO)


def workflows(path):
    doc = json.load(open(path, encoding="utf-8"))
    for r in doc.get("resources", []):
        if r.get("type") == "Microsoft.Logic/workflows":
            yield r["properties"]["definition"]


def importers(path):
    for dfn in workflows(path):
        if "Pagination_Loop_Incidents" in dfn.get("actions", {}):
            yield dfn


def syncers(path):
    for dfn in workflows(path):
        if "Check_SOCRadar_Write_Succeeded" in json.dumps(dfn):
            yield dfn


for path in (ROOT, IMPORT):
    found = False
    for dfn in importers(path):
        found = True
        acts = dfn["actions"]
        blob = json.dumps(dfn)

        # S2 -----------------------------------------------------------------------
        guard = acts.get("Check_Incidents_Complete")
        check(guard is not None,
              f"{rel(path)}: nothing checks whether the incident pagination finished")
        if guard:
            check("incidents_next_link" in json.dumps(guard["expression"]),
                  f"{rel(path)}: Check_Incidents_Complete does not look at the nextLink")
            check("incidents_truncated" in json.dumps(guard.get("else", {})),
                  f"{rel(path)}: a truncated incident list raises no flag")
            ra = guard["runAfter"].get("Pagination_Loop_Incidents") or []
            check("Failed" in ra and "TimedOut" in ra,
                  f"{rel(path)}: the completeness check is skipped when the loop times out, "
                  f"which is exactly when the list is truncated")
        verify = json.dumps(acts.get("Verify_Import_Complete", {}).get("expression", {}))
        check("incidents_truncated" in verify,
              f"{rel(path)}: the checkpoint can still move after a truncated dedup list")

        # S3 -----------------------------------------------------------------------
        check("?['is_success'], true)" not in blob,
              f"{rel(path)}: a response body that does not say is_success is still treated "
              f"as a successful page")
        check("?['is_success'], false)" in blob,
              f"{rel(path)}: the is_success check is gone entirely")

        # S4 -----------------------------------------------------------------------
        check("last(split(coalesce(items('For_Each_Missing_Entity')" not in blob,
              f"{rel(path)}: the backfill still takes the LAST '#' segment of the title, "
              f"which is the wrong alarm id when the title contains a '#'")
        check("For_Each_Missing_Entity')?['properties']?['title'], ''), '#')[1]" in blob,
              f"{rel(path)}: the backfill no longer reads the alarm id from the title")
    check(found, f"{rel(path)}: no import workflow found - the test is looking in the wrong place")

for path in (ROOT, SYNC):
    found = False
    for dfn in syncers(path):
        found = True

        def visit(node):
            if isinstance(node, dict):
                for k, v in node.items():
                    if k == "Check_SOCRadar_Write_Succeeded" and isinstance(v, dict):
                        yield v
                    yield from visit(v)
            elif isinstance(node, list):
                for v in node:
                    yield from visit(v)

        for act in visit(dfn):
            branch = act.get("else") or {}
            check(bool(branch.get("actions")),
                  f"{rel(path)}: SOCRadar refusing the status write leaves no trace")
    check(found, f"{rel(path)}: no sync workflow found - the test is looking in the wrong place")

if failures:
    for f in failures:
        print("  -", f)
    print(f"\n{len(failures)} problem(s) in {checks} assertions.")
    raise SystemExit(1)
print(f"Import integrity guards verified in {checks} assertions.")
