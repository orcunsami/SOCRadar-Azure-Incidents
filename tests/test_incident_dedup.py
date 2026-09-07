#!/usr/bin/env python3
"""SecurityIncident is an append log, so every query over it has to collapse to the newest
version of each incident before it filters, joins or counts.

Measured on a live workspace: three imported incidents produced six SecurityIncident rows,
two per incident eleven seconds apart, from creation alone -- a label change adds another.
Without "summarize arg_max(TimeGenerated, *) by IncidentNumber" that costs three different
ways, and the third is the one a customer sees:

  * a leftouter join multiplies its output rows
  * count() and avg() come out doubled
  * a "where Status != 'Closed'" matches a row written before the incident was closed, and
    "where not(Labels has 'Synced')" matches a row written before the Synced label was added
    -- so the rule that alerts on unsynced closed incidents fires for incidents that ARE
    synced and closed

A leftanti join is the one shape that does not need it: duplicate rows on the right add
nothing, and collapsing first can drop an incident whose newest version falls outside the
join's time window. Those are listed as exemptions and each one names its reason, so an
exemption cannot be added silently.
"""
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
DEDUP = "arg_max(TimeGenerated"

# path -> {line number: why this query does not need dedup}
EXEMPT = {
    "socradar-kql-queries.kql": {
        57: "leftanti join: duplicate right-hand rows add nothing, and collapsing first "
            "would drop incidents whose newest version predates the 24h window",
    },
}

failures = []
checks = 0


def check(cond, msg):
    global checks
    checks += 1
    if not cond:
        failures.append(msg)


def audit(text, where, path_key=None):
    """Every bare 'SecurityIncident' source line must be followed by the dedup, or exempted."""
    lines = text.split("\n")
    for i, l in enumerate(lines, start=1):
        if l.strip() != "SecurityIncident":
            continue
        exempt = EXEMPT.get(path_key or "", {}).get(i)
        following = "\n".join(lines[i:i + 3])
        if exempt:
            check(DEDUP not in following,
                  f"{where}:{i}: exempted as \"{exempt}\" but it dedupes anyway - "
                  f"remove the exemption or the dedup, they contradict each other")
            continue
        check(DEDUP in following,
              f"{where}:{i}: SecurityIncident is queried without "
              f"'summarize {DEDUP}, *) by IncidentNumber' - it will see stale versions of "
              f"each incident")


# --- the analytics rule that raises alerts, and the hunting query ----------------------
for rel in ["Analytic Rules/SOCRadarUnsyncedClosedIncident.yaml"]:
    p = ROOT / rel
    check(p.exists(), f"{rel}: missing - this check has gone blind")
    if p.exists():
        audit(p.read_text(), rel)

# --- the ARM template's embedded queries ------------------------------------------------
def walk(o, where):
    if isinstance(o, dict):
        for k, v in o.items():
            if k == "query" and isinstance(v, str) and "SecurityIncident" in v:
                check(DEDUP in v,
                      f"{where}: an embedded query reads SecurityIncident without the dedup")
            else:
                walk(v, where)
    elif isinstance(o, list):
        for v in o:
            walk(v, where)


for rel in ["azuredeploy.json"]:
    p = ROOT / rel
    check(p.exists(), f"{rel}: missing - this check has gone blind")
    if p.exists():
        walk(json.loads(p.read_text()), rel)

# --- the query file we hand to customers ------------------------------------------------
rel = "socradar-kql-queries.kql"
p = ROOT / rel
check(p.exists(), f"{rel}: missing - this check has gone blind")
if p.exists():
    audit(p.read_text(), rel, path_key=rel)
    # Calibration: if the file stopped mentioning SecurityIncident at all, the audit above
    # would pass by looking at nothing.
    check(p.read_text().count("SecurityIncident") >= 4,
          f"{rel}: fewer SecurityIncident queries than expected - the audit may be scanning "
          f"nothing")

print("\n".join(f"  - {f}" for f in failures))
print(f"{len(failures)} problem(s) in {checks} assertions." if failures
      else f"Every SecurityIncident query collapses to the newest version, "
           f"{len(EXEMPT.get(rel, {}))} documented exemption(s), {checks} assertions.")
sys.exit(1 if failures else 0)
