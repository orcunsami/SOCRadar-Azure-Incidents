#!/usr/bin/env python3
"""Break the workbook on purpose and prove tests/test_workbook.py notices.

Each mutation is a text edit applied to both templates that carry the workbook. A survivor is
BLIND and the run exits non-zero; an edit that changes nothing is STALE and fails too.

    python3 tests/mutate_workbook.py
"""
import os
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FILES = [os.path.join(REPO, "azuredeploy.json"), os.path.join(REPO, "Playbooks", "SOCRadar-Workbook", "azuredeploy.json")]
TEST = os.path.join(REPO, "tests", "test_workbook.py")

# Edits are made on the serializedData string itself (the ARM expression), where a quote inside the
# JSON text is a backslash-quote and a line break is a backslash-n.
MUTATIONS = [
    ("incident panel name lost", [('"name":"alarm-incident"', '"name":"alarm-incidentx"')]),
    ("incident number typed long", [("IncidentNumber:int", "IncidentNumber:long")]),
    ("sync panel reads SecurityIncident bare", [("union isfuzzy=true (datatable(IncidentNumber:int, Status:string, Labels:dynamic, TimeGenerated:datetime)[]), SecurityIncident", "SecurityIncident")]),
    ("alert join unguarded", [("union isfuzzy=true (datatable(SystemAlertId:string, ExtendedProperties:string)[]), SecurityAlert", "SecurityAlert")]),
    ("status panel counts rows", [("SOCRadar_Alarms_CL\\n| summarize arg_max(TimeGenerated, *) by AlarmId\\n| summarize Alarms=count() by Status", "SOCRadar_Alarms_CL\\n| summarize Alarms=count() by Status")]),
    ("custom details read in the flat shape", [("tostring(parse_json(tostring(parse_json(tostring(ExtendedProperties))[''Custom Details''])).AlarmId[0])", "tostring(parse_json(tostring(ExtendedProperties)).AlarmId)")]),
    ("synced label not read", [('has \\"Synced\\"', 'has \\"Done\\"')]),
    ("json broken", [('"name":"sync-status"}', '"name":"sync-status"')]),
]


def edit(path, edits):
    import json
    with open(path, encoding="utf-8") as handle:
        raw = handle.read()
    template = json.loads(raw)
    wb = next(r for r in template["resources"] if r["type"] == "Microsoft.Insights/workbooks")
    text = wb["properties"]["serializedData"]
    changed = False
    for old, new in edits:
        if old in text:
            text = text.replace(old, new)
            changed = True
    wb["properties"]["serializedData"] = text
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(template, indent=4, ensure_ascii=False) + ("\n" if raw.endswith("\n") else ""))
    return changed


def main():
    blind = []
    for name, edits in MUTATIONS:
        originals = {p: open(p, encoding="utf-8").read() for p in FILES}
        changed = False
        try:
            for p in FILES:
                changed = edit(p, edits) or changed
            if not changed:
                print("STALE  %-44s the edit changes nothing" % name)
                blind.append(name + " (stale)")
                continue
            rc = subprocess.run([sys.executable, TEST], cwd=REPO, capture_output=True, text=True, timeout=60,
                                env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1")).returncode
        finally:
            for p, text in originals.items():
                open(p, "w", encoding="utf-8").write(text)
        print(("BLIND  " if rc == 0 else "caught ") + "%-44s" % name)
        if rc == 0:
            blind.append(name)
    print("\nblind: %d of %d" % (len(blind), len(MUTATIONS)))
    return 1 if blind else 0


if __name__ == "__main__":
    sys.exit(main())
