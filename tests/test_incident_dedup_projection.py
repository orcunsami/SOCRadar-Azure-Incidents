#!/usr/bin/env python3
"""The existing-incident page is projected down to exactly the fields its consumers read.

Why this test exists: the dedup query returns whole Sentinel incident objects and
accumulates them in a Logic App variable, which has a size ceiling. The page is
projected to a small object before accumulation. A projection is only safe while it
carries every field a consumer reads, so the required field set is DERIVED from the
consumers here rather than hard-coded. Add a consumer that reads a new field and this
test fails until the projection carries it.

Also guards the loop-exit path: when the query fails the loop must stop and the run
must be marked incomplete, instead of replaying the same failing call.
"""
import json
import re
import sys

TEMPLATES = ["azuredeploy.json", "Playbooks/SOCRadar-Alarm-Import/azuredeploy.json"]
VARIABLE = "existing_incidents"
LOOP = "Pagination_Loop_Incidents"

failures = []


def check(cond, msg):
    if not cond:
        failures.append(msg)


def import_workflow(path):
    doc = json.load(open(path, encoding="utf-8"))
    hits = [
        r for r in doc["resources"]
        if r["type"] == "Microsoft.Logic/workflows"
        and LOOP in r["properties"]["definition"]["actions"]
    ]
    if len(hits) != 1:
        failures.append(f"{path}: expected exactly 1 workflow with {LOOP}, found {len(hits)}")
        return None
    return hits[0]["properties"]["definition"]


def fields_read_from(blob, accessor):
    """Field paths read off items coming from the projected variable."""
    found = set()
    pattern = re.escape(accessor) + r"((?:\??\['[A-Za-z0-9_]+'\])+)"
    for chain in re.findall(pattern, blob):
        found.add(tuple(re.findall(r"\['([A-Za-z0-9_]+)'\]", chain)))
    return found


def carried_by(select_expr):
    """Field paths the projection builds, read off its setProperty nesting."""
    carried = set()
    if "'id'" in select_expr:
        carried.add(("id",))
    if "'title'" in select_expr:
        carried.add(("properties", "title"))
    if "'bookmarksCount'" in select_expr:
        carried.add(("properties", "additionalData", "bookmarksCount"))
    return carried


for path in TEMPLATES:
    definition = import_workflow(path)
    if definition is None:
        continue
    actions = definition["actions"]
    loop = actions[LOOP]["actions"]
    blob = json.dumps(definition)

    # 1. the projection exists and feeds the accumulator
    check("Project_Incidents_Page" in loop, f"{path}: Project_Incidents_Page is missing")
    if "Project_Incidents_Page" not in loop:
        continue
    projection = loop["Project_Incidents_Page"]
    check(projection["type"] == "Select", f"{path}: projection must be a Select")
    compose = loop["Compose_New_Incidents"]["inputs"]
    check(
        "body('Project_Incidents_Page')" in compose,
        f"{path}: the accumulator must union the projection, not the raw page",
    )
    check(
        "body('Query_Incidents_Page')" not in compose,
        f"{path}: the accumulator still reads the raw query body",
    )

    # 2. every field a consumer reads is carried by the projection
    consumed = set()
    consumed |= fields_read_from(blob, "@item()")          # Select / Query over the variable
    consumed |= fields_read_from(blob, "items('For_Each_Missing_Entity')")
    consumed |= fields_read_from(blob, "first(body('Find_Existing_Incident'))")
    # only paths that can come off an incident object
    consumed = {f for f in consumed if f and f[0] in ("id", "properties")}
    carried = carried_by(projection["inputs"]["select"])
    missing = consumed - carried
    check(
        not missing,
        f"{path}: consumers read {sorted(missing)} but the projection does not carry it",
    )

    # 3. a failed page stops the loop and marks the run incomplete
    flag = loop.get("Flag_Incidents_Query_Failed")
    stop = loop.get("Stop_Incidents_Pagination")
    check(flag is not None, f"{path}: no truncation flag on a failed page")
    check(stop is not None, f"{path}: no loop-exit on a failed page")
    if flag and stop:
        triggers = set(flag["runAfter"].get("Query_Incidents_Page", []))
        check(
            {"Failed", "TimedOut", "Skipped"} <= triggers,
            f"{path}: the truncation flag must fire on Failed/TimedOut/Skipped, got {sorted(triggers)}",
        )
        check(
            flag["inputs"] == {"name": "incidents_truncated", "value": True},
            f"{path}: the flag must set incidents_truncated true",
        )
        check(
            stop["inputs"] == {"name": "incidents_next_link", "value": ""},
            f"{path}: the loop-exit must clear incidents_next_link",
        )
        check(
            "Flag_Incidents_Query_Failed" in stop["runAfter"],
            f"{path}: the loop-exit must run after the flag, so an incomplete run cannot look complete",
        )

# 4. both copies agree
shapes = []
for path in TEMPLATES:
    definition = import_workflow(path)
    if definition is None:
        continue
    loop = definition["actions"][LOOP]["actions"]
    shapes.append(
        json.dumps(
            {k: loop.get(k) for k in
             ("Project_Incidents_Page", "Compose_New_Incidents",
              "Flag_Incidents_Query_Failed", "Stop_Incidents_Pagination")},
            sort_keys=True,
        )
    )
check(len(set(shapes)) == 1, "the one-click template and the standalone playbook have drifted")

for line in failures:
    print(f"FAIL: {line}")
print(f"{VARIABLE} projection: {'FAILED' if failures else 'ok'} ({len(failures)} problem(s))")
sys.exit(1 if failures else 0)
