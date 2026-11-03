#!/usr/bin/env python3
"""The SOCRadar workbook: panels over SOCRadar_Alarms_CL, the alarm to incident join and the sync status.

The workbook is an ARM concat() of JSON text, so the template parses fine even when the JSON
inside is broken. This test renders the string the way ARM does and checks the result.

Run:  python3 tests/test_workbook.py
"""
import json
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FILES = ["azuredeploy.json", os.path.join("Playbooks", "SOCRadar-Workbook", "azuredeploy.json")]
REQUIRED = ["types-detail", "latest-status", "latest-severity", "alarm-incident", "sync-status"]
failures = []
checks = 0


def check(condition, message):
    global checks
    checks += 1
    if not condition:
        failures.append(message)


def render(path):
    with open(os.path.join(REPO, path), encoding="utf-8") as handle:
        template = json.load(handle)
    resource = next(r for r in template["resources"] if r["type"] == "Microsoft.Insights/workbooks")
    expr = resource["properties"]["serializedData"]
    body = re.match(r"\[concat\((.*)\)\]$", expr, re.S)
    if body is None:
        return None, expr
    tokens = re.findall(r"'((?:[^']|'')*)'|(variables\('AlarmsTableName'\))", body.group(1))
    text = "".join(t[0].replace("''", "'") if not t[1] else "SOCRadar_Alarms_CL" for t in tokens)
    return json.loads(text), expr


rendered = {}
for path in FILES:
    try:
        doc, expr = render(path)
    except (ValueError, StopIteration) as exc:
        check(False, f"{path}: the workbook does not render to JSON: {exc}")
        continue
    check(doc is not None, f"{path}: serializedData must be a concat() expression")
    if doc is None:
        continue
    rendered[path] = doc
    items = {i["name"]: i for i in doc["items"]}
    check(len(items) == len(doc["items"]), f"{path}: panel names must be unique")
    for name in REQUIRED:
        check(name in items, f"{path}: panel {name} is missing")
    for item in doc["items"]:
        if item["type"] != 3:
            continue
        c = item["content"]
        check(c.get("timeContext", {}).get("durationMs") and c.get("resourceType") == "microsoft.operationalinsights/workspaces",
              f"{path}: panel {item['name']} needs a time context and the workspace resource type")
        q = c["query"]
        # A workspace without Defender data has no SecurityAlert / SecurityIncident table yet: a bare
        # reference makes the panel an error instead of an empty list.
        for table in ("SecurityAlert", "SecurityIncident"):
            for m in re.finditer(r"\b%s\b" % table, q):
                head = q[max(0, m.start() - 60):m.start()]
                check("isfuzzy=true" in head or "isfuzzy=true" in q[:m.start()].split("\n")[-1] or
                      re.search(r"union isfuzzy=true \(datatable\([^)]*\)\[\]\), $", head) is not None,
                      f"{path}: panel {item['name']} reads {table} without a union isfuzzy=true guard")
    if "alarm-incident" in items:
        q = items["alarm-incident"]["content"]["query"]
        check("IncidentNumber:int" in q, f"{path}: the empty-table stand-in must type IncidentNumber as int, "
              "as SecurityIncident does, or the union splits the column in two and the join finds nothing")
        check("tostring(parse_json(tostring(parse_json(tostring(ExtendedProperties))['Custom Details'])).AlarmId[0])" in q,
              f"{path}: the alert to alarm join must read the double-encoded Custom Details shape measured live")
        check("mv-expand AlertId = AlertIds" in q and "$left.SystemAlertId == $right.AlertId" in q,
              f"{path}: the incident join must go through AlertIds")
    if "sync-status" in items:
        q = items["sync-status"]["content"]["query"]
        check('has "SOCRadar"' in q and 'has "Synced"' in q and "IncidentNumber:int" in q,
              f"{path}: the sync panel must count SOCRadar incidents by the Synced label")
    for name in ("types-detail", "latest-status", "latest-severity"):
        if name in items:
            check("summarize arg_max(TimeGenerated, *) by AlarmId" in items[name]["content"]["query"],
                  f"{path}: {name} must count alarms, not rows (an alarm is written again whenever it is re-imported)")

if len(rendered) == 2:
    a, b = rendered.values()
    check(a == b, "the workbook differs between azuredeploy.json and Playbooks/SOCRadar-Workbook")

if failures:
    print("WORKBOOK CHECK FAILED\n")
    for item in failures:
        print("  - " + item)
    print(f"\n{len(failures)} problem(s) in {checks} checks.")
    sys.exit(1)
print(f"Workbook: renders to JSON in both templates, {len(REQUIRED)} new panels, joins guarded, verified in {checks} checks.")
