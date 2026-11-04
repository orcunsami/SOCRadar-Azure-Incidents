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
  S6  The backfill picks incidents with no bookmark, and an alarm with no IoC never gets one,
      so the same 60 incidents were re-read on every run. The backfill now writes an
      entity-less bookmark for an alarm it read and found empty, and only for that case:
      a failed read must stay unmarked so the next run retries it.
  S7  The IoC playbook read the alarm id with last(split(title, '#')), the same wrong-segment
      bug as S4, in a different file.

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
        # S6 -----------------------------------------------------------------------
        flt = json.dumps(acts.get("Filter_Incidents_Missing_Entities", {}).get("inputs", {}))
        check("['bookmarksCount'], 0), 0)" in flt,
              f"{rel(path)}: the backfill no longer skips incidents that already have a bookmark, "
              f"so the no-IoC marker would not stop the re-selection")

        def find(node, name):
            if isinstance(node, dict):
                if name in node and isinstance(node[name], dict):
                    return node[name]
                for v in node.values():
                    r = find(v, name)
                    if r is not None:
                        return r
            elif isinstance(node, list):
                for v in node:
                    r = find(v, name)
                    if r is not None:
                        return r
            return None

        has = find(acts.get("Backfill_Missing_Entities"), "BF_Check_Has_Entities")
        guard = ((has or {}).get("else") or {}).get("actions", {}).get("BF_Check_Alarm_Was_Read")
        check(guard is not None,
              f"{rel(path)}: an alarm with no IoC is never marked, so it is re-read on every run")
        if guard:
            cond = json.dumps(guard.get("expression", {}))
            check("body('Fetch_Backfill_Alarm')" in cond and "'data'" in cond and "greater" in cond,
                  f"{rel(path)}: the no-IoC marker is not conditioned on the alarm having been read")
            inner = guard.get("actions", {})
            mark = inner.get("BF_Create_NoIoC_Bookmark", {})
            rel_act = inner.get("BF_Relate_NoIoC_Bookmark", {})
            body = mark.get("inputs", {}).get("body", {}).get("properties", {})
            check(mark.get("inputs", {}).get("method") == "PUT" and body.get("entityMappings") == [],
                  f"{rel(path)}: the marker must be an entity-less bookmark")
            check("/bookmarks/50c8ada7-0000-4000-8000-" in mark.get("inputs", {}).get("uri", ""),
                  f"{rel(path)}: the marker bookmark id is not the per-alarm id the IoC bookmark uses")
            check("/relations/50c8ada7-0000-4000-9000-" in rel_act.get("inputs", {}).get("uri", "")
                  and "BF_Create_NoIoC_Bookmark" in json.dumps(rel_act.get("runAfter", {})),
                  f"{rel(path)}: the marker is never related to the incident, so bookmarksCount stays 0")
            check("Failed" not in json.dumps(rel_act.get("runAfter", {})),
                  f"{rel(path)}: a failed marker write must not be swallowed")
    check(found, f"{rel(path)}: no import workflow found - the test is looking in the wrong place")

IOC = os.path.join(REPO, "Playbooks", "SOCRadar-IOC-Enrichment", "azuredeploy.json")
found = False
for dfn in workflows(IOC):
    found = True
    expr = json.dumps(dfn.get("actions", {}).get("Extract_Alarm_Id", {}).get("inputs", ""))
    # S7 -----------------------------------------------------------------------------
    check("last(split(" not in expr,
          f"{rel(IOC)}: the IoC playbook still takes the LAST '#' segment of the title")
    check("'#')[1]" in expr,
          f"{rel(IOC)}: the IoC playbook no longer reads the alarm id from the title")
check(found, f"{rel(IOC)}: no workflow found")

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
