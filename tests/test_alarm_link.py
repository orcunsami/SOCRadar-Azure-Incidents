#!/usr/bin/env python3
"""Pin the "View in SOCRadar" link and Sync's parse of it.

The platform opens an alarm at
  /app/company/<company>/alarm-management?tab=<tab>&field=alarmId&operator=equals&value=<alarm id>
The old /company/<company>/alarm/<id> shape returns 404. Approved alarms live under
tab=approved, alarms still in review under tab=potential; the wrong tab shows an empty list.
The import picks the tab from is_approved. The alert-backed rule has no approval column
and always uses tab=approved.

Sync falls back to the alarm URL entity when an incident has neither the alarm label nor
'#<id>' in its title. Incidents created before this change carry the old shape, so Sync
must read both.

Run:  python3 tests/test_alarm_link.py
"""

import json
import os

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
A = "items('For_Each_Alarm')"
DESC_LINK = ("'View in SOCRadar: https://platform.socradar.com/app/company/', parameters('CompanyId'), "
             f"'/alarm-management?tab=', if(equals({A}?['is_approved'], false), 'potential', 'approved'), "
             f"'&field=alarmId&operator=equals&value=', {A}?['alarm_id']")
KQL_LINK = ('strcat("https://platform.socradar.com/app/company/", CompanyId, '
            '"/alarm-management?tab=approved&field=alarmId&operator=equals&value=", AlarmId)')
URL = "string(coalesce(item()?['properties']?['url'], ''))"
FIRST = "string(first(body('Filter_Alarm_Url_Entities'))?['properties']?['url'])"
# Only SOCRadar URLs count: IoC enrichment also adds URLs from the alarm text as entities.
SYNC_WHERE = (f"@and(equals(item()?['kind'], 'Url'), contains({URL}, 'platform.socradar.com/'), "
              f"or(contains({URL}, '/alarm/'), contains({URL}, 'field=alarmId')))")
SYNC_EXTRACT = (f"@if(greater(length(body('Filter_Alarm_Url_Entities')), 0), if(contains({FIRST}, 'field=alarmId'), "
                f"first(split(first(split(first(split(last(split({FIRST}, 'value=')), '&')), '#')), '/')), "
                f"first(split(first(split(last(split({FIRST}, '/alarm/')), '?')), '/'))), '')")
README_SYNC = "(`.../alarm-management?...&value=<id>`, or the older\n`.../alarm/<id>`)"

failures = []
checks = 0


def check(condition, message):
    global checks
    checks += 1
    if not condition:
        failures.append(message)


def read(rel):
    return open(os.path.join(REPO, rel), encoding="utf-8").read()


def find(o, name):
    if isinstance(o, dict):
        for k, v in o.items():
            if k == name and isinstance(v, dict) and "type" in v:
                return v
            r = find(v, name)
            if r is not None:
                return r
    elif isinstance(o, list):
        for v in o:
            r = find(v, name)
            if r is not None:
                return r


for rel in ["azuredeploy.json", "Playbooks/SOCRadar-Alarm-Import/azuredeploy.json"]:
    s = read(rel)
    check(s.count(DESC_LINK) == 1, f"{rel}: description link missing or changed")
    check(s.count(KQL_LINK.replace('"', '\\"')) == 1, f"{rel}: alert-backed AlarmUrl missing or changed")

for rel in ["socradar-kql-queries.kql", "Analytic Rules/SOCRadarCriticalAlarmDetection.yaml"]:
    check(read(rel).count(KQL_LINK) == 1, f"{rel}: alarm link missing or changed")

syncs = []
for rel in ["azuredeploy.json", "Playbooks/SOCRadar-Alarm-Sync/azuredeploy.json"]:
    t = json.loads(read(rel))
    lookup = find(t, "Check_Needs_Entity_Lookup")["actions"]
    syncs.append(json.dumps(lookup, sort_keys=True))
    check(lookup["Filter_Alarm_Url_Entities"]["inputs"]["where"] == SYNC_WHERE,
          f"{rel}: Sync does not accept both the old and the new alarm URL")
    check(lookup["Alarm_ID_From_Entities"]["inputs"] == SYNC_EXTRACT,
          f"{rel}: Sync does not read the alarm id from both URL shapes")
check(len(syncs) == 2 and syncs[0] == syncs[1], "root and playbook Sync URL lookup differ")

for rel in ["azuredeploy.json", "Playbooks/SOCRadar-Alarm-Import/azuredeploy.json", "socradar-kql-queries.kql",
            "Analytic Rules/SOCRadarCriticalAlarmDetection.yaml", "README.md"]:
    check("platform.socradar.com/company/" not in read(rel), f"{rel}: old 404 link shape is back")
check(README_SYNC in read("README.md"), "README does not describe both URL shapes Sync reads")


def parse(url):
    # Python mirror of SYNC_WHERE + SYNC_EXTRACT, run on real link shapes. None = filtered out.
    if "platform.socradar.com/" not in url or ("/alarm/" not in url and "field=alarmId" not in url):
        return None
    if "field=alarmId" in url:
        return url.split("value=")[-1].split("&")[0].split("#")[0].split("/")[0]
    return url.split("/alarm/")[-1].split("?")[0].split("/")[0]


for url, want in [
    ("https://platform.socradar.com/app/company/1000/alarm-management?tab=approved&field=alarmId&operator=equals&value=2000001", "2000001"),
    ("https://platform.socradar.com/app/company/1000/alarm-management?tab=potential&field=alarmId&operator=equals&value=2000002", "2000002"),
    ("https://platform.socradar.com/app/company/1000/alarm-management?tab=approved&field=alarmId&operator=equals&value=2000004/", "2000004"),
    ("https://platform.socradar.com/app/company/1000/alarm-management?tab=approved&field=alarmId&operator=equals&value=2000005#x", "2000005"),
    ("https://platform.socradar.com/company/1000/alarm/2000003", "2000003"),
    ("https://example.com/alarm/999", None),
]:
    check(parse(url) == want, f"parse({url}) != {want}")

if failures:
    for f in failures:
        print("FAIL", f)
    raise SystemExit(1)
print(f"Alarm link verified in {checks} assertions.")
