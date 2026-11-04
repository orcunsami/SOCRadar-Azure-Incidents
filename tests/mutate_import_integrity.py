#!/usr/bin/env python3
"""Break the no-IoC marker and the alarm-id reader on purpose and prove
tests/test_import_integrity.py notices.

Each mutation is applied to one copy of the tree and the test is run. A mutation that survives is
BLIND, and one where the test dies without its own failure line is a CRASH; both fail the run.

    python3 tests/mutate_import_integrity.py
"""
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

READ_GUARD = "@length(coalesce(body('Fetch_Backfill_Alarm')?['data'], json('[]')))"
FILTER = "\"where\": \"@and(equals(coalesce(item()?['properties']?['additionalData']?['bookmarksCount'], 0), 0)"

MUTATIONS = []
for f in IMPORTERS:
    MUTATIONS += [
        (f"{f}: the marker is written without checking the alarm was read", f, READ_GUARD, "@add(1, 0)"),
        (f"{f}: the marker bookmark carries an entity", f, '"entityMappings": []', '"entityMappings": ["x"]'),
        (f"{f}: the marker is never created", f, '"BF_Create_NoIoC_Bookmark": {', '"BF_Create_Other": {'),
        (f"{f}: the marker is never related to the incident", f, '"BF_Relate_NoIoC_Bookmark": {', '"BF_Relate_Other": {'),
        (f"{f}: the filter stops skipping incidents with a bookmark", f, FILTER, FILTER.replace("0), 0)", "0), 1)")),
        (f"{f}: a failed marker write is swallowed", f,
         '"BF_Create_NoIoC_Bookmark": [\n', '"BF_Create_NoIoC_Bookmark": [\n                                                                "Failed",\n'),
    ]
MUTATIONS.append((f"{IOC}: the alarm id is read from the last '#' segment", IOC,
                  "split(split(coalesce(triggerBody()?['object']?['properties']?['title'], ''), '#')[1], ' ')[0]",
                  "first(split(last(split(coalesce(triggerBody()?['object']?['properties']?['title'], ''), '#')), ' '))"))

blind = 0
for label, rel, old, new in MUTATIONS:
    with tempfile.TemporaryDirectory() as tmp:
        work = os.path.join(tmp, "repo")
        shutil.copytree(REPO, work, ignore=shutil.ignore_patterns(".git", "__pycache__"))
        path = os.path.join(work, rel)
        text = open(path, encoding="utf-8").read()
        if old not in text:
            print(f"  STALE {label}: pattern not found")
            blind += 1
            continue
        open(path, "w", encoding="utf-8").write(text.replace(old, new, 1))
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
print(f"blind or stale: {blind} of {len(MUTATIONS)}")
sys.exit(1 if blind else 0)
