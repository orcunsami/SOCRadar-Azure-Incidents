#!/usr/bin/env python3
"""Break the no-IoC marker and the IoC playbook's alarm-id reader on purpose and prove
tests/test_import_integrity.py notices.

Each mutation is applied to one copy of the tree and the test is run. A mutation that survives is
BLIND, and one where the test dies without its own failure summary is a CRASH; both fail the run.
The breaks are made on the parsed JSON (branch, dependency, threshold, id), not on a text snippet,
because a test that only checks substrings passes most structural breaks.

    python3 tests/mutate_import_integrity.py
"""
import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMPORTERS = ["azuredeploy.json", os.path.join("Playbooks", "SOCRadar-Alarm-Import", "azuredeploy.json")]
IOC = os.path.join("Playbooks", "SOCRadar-IOC-Enrichment", "azuredeploy.json")
TEST = os.path.join("tests", "test_import_integrity.py")
BANNER = "problem(s) in"
ALARM = "substring(concat('000000000000', outputs('Extract_Backfill_Alarm_Id')), length(outputs('Extract_Backfill_Alarm_Id')), 12)"


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


def importer_actions(doc):
    for r in doc["resources"]:
        if r.get("type") == "Microsoft.Logic/workflows":
            acts = r["properties"]["definition"]["actions"]
            if "Backfill_Missing_Entities" in acts:
                yield acts


def on_importers(fn):
    def apply(doc):
        n = 0
        for acts in importer_actions(doc):
            fn(acts)
            n += 1
        return n > 0
    return apply


def parts(acts):
    has = find(acts["Backfill_Missing_Entities"], "BF_Check_Has_Entities")
    guard = has["else"]["actions"]["BF_Check_Alarm_Was_Read"]
    return has, guard, guard["actions"]["BF_Create_NoIoC_Bookmark"], guard["actions"]["BF_Relate_NoIoC_Bookmark"]


def m_runafter(a):
    parts(a)[0]["runAfter"]["BF_Combine_Entity_Mappings"].append("Failed")


def m_threshold(a):
    parts(a)[1]["expression"]["and"][0]["greater"][1] = -1


def m_always(a):
    g = parts(a)[1]
    g["expression"] = {"or": [g["expression"]["and"][0], {"equals": [1, 1]}]}


def m_const_id(a):
    c = parts(a)[2]["inputs"]
    c["uri"] = c["uri"].replace("@{" + ALARM + "}", "000000000000")


def m_collide(a):
    c = parts(a)[2]["inputs"]
    c["uri"] = c["uri"].replace("50c8ada8", "50c8ada7")


def m_then_branch(a):
    has, _, mark, _ = parts(a)
    has["actions"]["BF_Create_NoIoC_Bookmark"] = copy.deepcopy(mark)


def m_points_at_ioc(a):
    parts(a)[3]["inputs"]["body"]["properties"]["relatedResourceId"] = "@{body('BF_Create_IoC_Bookmark')?['id']}"


def m_wrong_incident(a):
    r = parts(a)[3]["inputs"]
    r["uri"] = r["uri"].replace("@{items('For_Each_Missing_Entity')?['id']}", "")


def m_relate_runafter(a):
    parts(a)[3]["runAfter"] = {}


def m_swallow(a):
    parts(a)[3]["runAfter"]["BF_Create_NoIoC_Bookmark"] = ["Succeeded", "Failed"]


def m_to_then(a):
    has, guard, _, _ = parts(a)
    has["actions"]["BF_Check_Alarm_Was_Read"] = has["else"]["actions"].pop("BF_Check_Alarm_Was_Read")


def m_filter(a):
    f = a["Filter_Incidents_Missing_Entities"]["inputs"]
    f["where"] = f["where"].replace("0), 0)", "0), 1)", 1)


def m_label(a):
    parts(a)[2]["inputs"]["body"]["properties"]["labels"] = ["SOCRadar"]


def m_entity(a):
    parts(a)[2]["inputs"]["body"]["properties"]["entityMappings"] = [{"entityType": "IP"}]


AST = [
    ("a failed read is marked as empty", m_runafter),
    ("an empty fetch is marked (threshold below zero)", m_threshold),
    ("the marker is written whether or not the alarm was read", m_always),
    ("every alarm shares one marker id", m_const_id),
    ("the marker id collides with the IoC bookmark id", m_collide),
    ("the marker is also written when entities were found", m_then_branch),
    ("the marker relation points at the IoC bookmark", m_points_at_ioc),
    ("the marker relation targets the wrong incident", m_wrong_incident),
    ("the marker relation has no dependency on the bookmark", m_relate_runafter),
    ("a failed marker write is swallowed", m_swallow),
    ("the marker guard moves to the entities-found branch", m_to_then),
    ("the filter stops skipping incidents that have a bookmark", m_filter),
    ("the marker bookmark loses its label", m_label),
    ("the marker bookmark carries an entity", m_entity),
]

IOC_TEXT = [
    ("the alarm id is read from the last '#' segment",
     "split(split(concat(coalesce(triggerBody()?['object']?['properties']?['title'], ''), '#'), '#')[1], ' ')[0]",
     "first(split(last(split(coalesce(triggerBody()?['object']?['properties']?['title'], ''), '#')), ' '))"),
    ("a title with no '#' relies on if() skipping the unused branch",
     "split(split(concat(coalesce(triggerBody()?['object']?['properties']?['title'], ''), '#'), '#')[1], ' ')[0]",
     "if(contains(coalesce(triggerBody()?['object']?['properties']?['title'], ''), '#'), split(split(coalesce(triggerBody()?['object']?['properties']?['title'], ''), '#')[1], ' ')[0], '')"),
    ("the second word is read instead of the first",
     "' ')[0]\"", "' ')[1]\""),
    ("the title is split on '@'",
     "'#'), '#')[1]", "'#'), '@')[1]"),
    ("the segment index moves",
     "'#')[1], ' ')", "'#')[2], ' ')"),
]

JOBS = []
for f in IMPORTERS:
    for label, fn in AST:
        JOBS.append((f"{f}: {label}", f, ("ast", on_importers(fn))))
for label, old, new in IOC_TEXT:
    JOBS.append((f"{IOC}: {label}", IOC, ("text", old, new)))

blind = 0
for label, rel, spec in JOBS:
    with tempfile.TemporaryDirectory() as tmp:
        work = os.path.join(tmp, "repo")
        shutil.copytree(REPO, work, ignore=shutil.ignore_patterns(".git", "__pycache__"))
        path = os.path.join(work, rel)
        text = open(path, encoding="utf-8").read()
        if spec[0] == "ast":
            doc = json.loads(text)
            try:
                applied = spec[1](doc)
            except (KeyError, IndexError, TypeError):
                applied = False
            if not applied:
                print(f"  STALE {label}: the part to break was not found")
                blind += 1
                continue
            open(path, "w", encoding="utf-8").write(json.dumps(doc, indent=4))
        else:
            if spec[1] not in text:
                print(f"  STALE {label}: pattern not found")
                blind += 1
                continue
            open(path, "w", encoding="utf-8").write(text.replace(spec[1], spec[2], 1))
        try:
            result = subprocess.run([sys.executable, TEST], cwd=work, capture_output=True, text=True, timeout=60)
            code = result.returncode
            # Only the test's own failure summary counts as caught: a traceback also exits non-zero.
            banner = code == 1 and BANNER in result.stdout
        except subprocess.TimeoutExpired:
            code, banner = 124, False
        if code == 0:
            print(f"  BLIND {label}")
            blind += 1
        elif not banner:
            print(f"  CRASH {label}: the test died (rc {code}) without its failure summary")
            blind += 1
        else:
            print(f"  caught {label}")
print(f"blind or stale: {blind} of {len(JOBS)}")
sys.exit(1 if blind else 0)
