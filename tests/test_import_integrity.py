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

ALARM = "substring(concat('000000000000', outputs('Extract_Backfill_Alarm_Id')), length(outputs('Extract_Backfill_Alarm_Id')), 12)"
FILTER_WHERE = ("@and(equals(coalesce(item()?['properties']?['additionalData']?['bookmarksCount'], 0), 0), "
                "contains(coalesce(item()?['properties']?['title'], ''), '#'))")
READ_LENGTH = "@length(coalesce(body('Fetch_Backfill_Alarm')?['data'], json('[]')))"
MARK_URI = ("@{parameters('ManagementBaseUrl')}/subscriptions/@{parameters('SubscriptionId')}/resourceGroups/"
            "@{parameters('ResourceGroupName')}/providers/Microsoft.OperationalInsights/workspaces/"
            "@{parameters('WorkspaceName')}/providers/Microsoft.SecurityInsights/bookmarks/50c8ada8-0000-4000-8000-@{"
            + ALARM + "}?api-version=2024-10-01-preview")
RELATE_URI = ("@{parameters('ManagementBaseUrl')}@{items('For_Each_Missing_Entity')?['id']}"
              "/relations/50c8ada8-0000-4000-9000-@{" + ALARM + "}?api-version=2023-11-01")
IOC_ALARM_ID = ("@split(split(concat(coalesce(triggerBody()?['object']?['properties']?['title'], ''), '#'), '#')[1], ' ')[0]")


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
        flt = acts.get("Filter_Incidents_Missing_Entities", {}).get("inputs", {})
        check(flt.get("where") == FILTER_WHERE,
              f"{rel(path)}: the backfill filter changed; it must keep skipping incidents that "
              f"already have a bookmark, or the no-IoC marker no longer stops the re-selection")

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
        check(has is not None, f"{rel(path)}: the backfill has no entity check")
        has = has or {}
        check(has.get("runAfter") == {"BF_Combine_Entity_Mappings": ["Succeeded"]},
              f"{rel(path)}: the entity check must run only after a successful read, "
              f"or a failed read gets marked as empty")
        check(has.get("expression") == {"and": [{"greater": ["@length(outputs('BF_Combine_Entity_Mappings'))", 0]}]},
              f"{rel(path)}: the entity check no longer asks whether any entity was found")
        then_names = json.dumps(has.get("actions", {}))
        check("NoIoC" not in then_names,
              f"{rel(path)}: the no-IoC marker is also written when entities WERE found")
        else_actions = (has.get("else") or {}).get("actions", {})
        check(list(else_actions) == ["BF_Check_Alarm_Was_Read"],
              f"{rel(path)}: an alarm with no IoC is not marked through exactly one guarded step")
        guard = else_actions.get("BF_Check_Alarm_Was_Read") or {}
        check(guard.get("runAfter") == {},
              f"{rel(path)}: the marker guard has an unexpected dependency")
        check(guard.get("expression") == {"and": [{"greater": [READ_LENGTH, 0]}]},
              f"{rel(path)}: the marker is not conditioned on the alarm having been read "
              f"(an empty fetch must stay unmarked so the next run retries it)")
        check((guard.get("else") or {}).get("actions") == {},
              f"{rel(path)}: an unread alarm takes an action it should not")
        inner = guard.get("actions", {})
        check(sorted(inner) == ["BF_Create_NoIoC_Bookmark", "BF_Relate_NoIoC_Bookmark"],
              f"{rel(path)}: the marker is not exactly one bookmark and one relation")
        mark = inner.get("BF_Create_NoIoC_Bookmark", {})
        rel_act = inner.get("BF_Relate_NoIoC_Bookmark", {})
        check(mark.get("runAfter") == {},
              f"{rel(path)}: the marker bookmark has an unexpected dependency")
        mi = mark.get("inputs", {})
        check(mi.get("method") == "PUT" and mi.get("uri") == MARK_URI,
              f"{rel(path)}: the marker bookmark must use its own per-alarm id, "
              f"never the id of the IoC bookmark (it would overwrite it)")
        check(mi.get("body", {}).get("properties", {}).get("entityMappings") == [],
              f"{rel(path)}: the marker must be an entity-less bookmark")
        check("Auto-IoC-None" in mi.get("body", {}).get("properties", {}).get("labels", []),
              f"{rel(path)}: the marker bookmark is not labelled")
        ri = rel_act.get("inputs", {})
        check(ri.get("method") == "PUT" and ri.get("uri") == RELATE_URI,
              f"{rel(path)}: the marker relation targets the wrong incident or id")
        check(ri.get("body") == {"properties": {"relatedResourceId": "@{body('BF_Create_NoIoC_Bookmark')?['id']}"}},
              f"{rel(path)}: the marker relation does not point at the marker bookmark")
        check(rel_act.get("runAfter") == {"BF_Create_NoIoC_Bookmark": ["Succeeded"]},
              f"{rel(path)}: a failed marker write must not be swallowed")
        ioc = find(acts.get("Backfill_Missing_Entities"), "BF_Create_IoC_Bookmark") or {}
        check("/bookmarks/50c8ada7-0000-4000-8000-" in ioc.get("inputs", {}).get("uri", "")
              and "50c8ada7" not in mi.get("uri", ""),
              f"{rel(path)}: the IoC bookmark id and the marker id must stay different")
    check(found, f"{rel(path)}: no import workflow found - the test is looking in the wrong place")

IOC = os.path.join(REPO, "Playbooks", "SOCRadar-IOC-Enrichment", "azuredeploy.json")
found = False
for dfn in workflows(IOC):
    found = True
    expr = dfn.get("actions", {}).get("Extract_Alarm_Id", {}).get("inputs", "")
    # S7 -----------------------------------------------------------------------------
    check(expr == IOC_ALARM_ID,
          f"{rel(IOC)}: the IoC playbook must read the alarm id from the FIRST '#' segment, "
          f"and must not depend on if() skipping the unused branch for a title with no '#'")
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
