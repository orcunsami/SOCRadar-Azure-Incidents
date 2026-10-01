#!/usr/bin/env python3
"""Shipped queries whose logic contradicted what the README says they do.

  - SOCRadarAlarmVolumeSpike.yaml: the README says "an alarm type exceeds 3x its own 7-day
    average", but the baseline was one number for all types together, so a single busy
    type fired every hour and a quiet type among busy ones never fired.
  - socradar-kql-queries.kql, "High/Critical alarms not yet closed": the right side of the
    left outer join dropped closed incidents first, so a closed incident matched nothing and
    its alarm was listed as not closed.

  - Hunting query "SOCRadar Alarm Overview": count() on an append-only table counts an alarm
    once per ingested row, so it overstates after a mode switch. It counts AlarmId now.

Run:  python3 tests/test_query_logic.py
"""

import os
import re
import sys

import yaml

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
failures = []
checks = 0


def check(condition, message):
    global checks
    checks += 1
    if not condition:
        failures.append(message)


# 1. Volume spike: the baseline is per alarm type and is joined back on that type.
with open(os.path.join(REPO, "Analytic Rules", "SOCRadarAlarmVolumeSpike.yaml")) as handle:
    query = yaml.safe_load(handle)["query"]
baseline = re.search(r"let baseline = (.*?);", query, re.S)
check(baseline is not None, "spike rule: no 'let baseline' found, this check has gone blind")
if baseline:
    check(re.search(r"summarize[^|;]*\bby\s+AlarmMainType", baseline.group(1)) is not None,
          "spike rule: the 7-day baseline must be summarized by AlarmMainType, not across all types")
check("toscalar(baseline)" not in query,
      "spike rule: toscalar(baseline) compares one type with the average of all types")
check(re.search(r"join[^|]*\bbaseline\b[^|]*on\s+AlarmMainType", query) is not None,
      "spike rule: the recent counts must be joined to the baseline on AlarmMainType")

# 2. "High/Critical alarms not yet closed": closed incidents must reach the join.
with open(os.path.join(REPO, "socradar-kql-queries.kql")) as handle:
    text = handle.read()
section = re.search(r"// High/Critical alarms not yet closed\n(.*?)\n// Alarm trends", text, re.S)
check(section is not None, "kql: 'High/Critical alarms not yet closed' section not found")
if section:
    body = section.group(1)
    sub = re.search(r"join kind=leftouter \((.*?)\n\) on AlarmId", body, re.S)
    check(sub is not None, "kql: the leftouter join subquery was not found")
    if sub:
        check('Status != "Closed"' not in sub.group(1),
              "kql: the join subquery drops closed incidents, so closed alarms are listed as not closed")
    after = body.split(") on AlarmId", 1)[-1]
    check(re.search(r'isempty\(Status1\)\s+or\s+Status1\s*!=\s*"Closed"', after) is not None,
          "kql: after the join, keep rows with no incident or an incident that is not Closed")

# 3. Alarm Overview counts alarms, not rows: the table is append-only, so a mode switch
#    writes the same alarm twice (README, Incident mode).
import json

with open(os.path.join(REPO, "azuredeploy.json")) as handle:
    template = json.load(handle)
overview = [r for r in template["resources"]
            if r.get("type", "").endswith("savedSearches")
            and r["properties"].get("displayName") == "SOCRadar Alarm Overview"]
check(len(overview) == 1, "hunting: SOCRadar Alarm Overview not found, this check has gone blind")
if overview:
    check("dcount(AlarmId)" in overview[0]["properties"]["query"],
          "hunting: Alarm Overview must count distinct AlarmId, count() double-counts re-ingested alarms")

if failures:
    for message in failures:
        print("FAIL " + message)
    sys.exit(1)
print(f"Spike rule baseline and not-yet-closed query verified in {checks} assertions.")
