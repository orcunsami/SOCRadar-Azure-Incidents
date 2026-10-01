#!/usr/bin/env python3
"""A closed incident must not drop out of Sync's reach after one polling interval.

Sync lists closed SOCRadar incidents modified inside a lookback window and writes each
closure back to SOCRadar. The window used to be 2 x PollingIntervalMinutes (10 minutes by
default) with no checkpoint, so an incident whose write failed, or that was closed while
Sync was disabled or erroring for more than that, was never looked at again and the
SOCRadar alarm stayed OPEN. The Synced label already stops a second write, so the window
can be wide; a Filter array drops the synced incidents before the Foreach so a wide
window does not cost an action per incident per run.

The incidents query also retried the same page for the full 10-minute Until timeout when
it failed (EXP-AZURE-0136). It now flags the failure, stops, and ends the run Failed.

Run:  python3 tests/test_sync_window.py
"""

import json
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATES = {
    "azuredeploy.json": os.path.join(REPO, "azuredeploy.json"),
    "Playbooks/SOCRadar-Alarm-Sync": os.path.join(REPO, "Playbooks", "SOCRadar-Alarm-Sync", "azuredeploy.json"),
}
MIN_WINDOW_HOURS = 24

failures = []
checks = 0


def check(condition, message):
    global checks
    checks += 1
    if not condition:
        failures.append(message)


def sync_actions(path):
    with open(path, encoding="utf-8") as handle:
        template = json.load(handle)
    for resource in template["resources"]:
        if resource.get("type") == "Microsoft.Logic/workflows":
            actions = resource["properties"]["definition"]["actions"]
            if "For_Each_Incident" in actions:
                return actions
    return None


for label, path in TEMPLATES.items():
    actions = sync_actions(path)
    if actions is None:
        failures.append(f"{label}: no sync workflow found, this check has gone blind")
        continue

    # The window: a fixed span of at least a day, not a multiple of the polling interval.
    lookback = (actions.get("Calculate_Lookback_Time") or {}).get("inputs", "")
    hours = None
    prefix = "@addHours(utcNow(), -"
    if isinstance(lookback, str) and lookback.startswith(prefix) and lookback.endswith(")"):
        number = lookback[len(prefix):-1]
        hours = int(number) if number.isdigit() else None
    check(hours is not None and hours >= MIN_WINDOW_HOURS,
          f"{label}: Calculate_Lookback_Time must reach back at least {MIN_WINDOW_HOURS} h, got {lookback!r}")
    check("PollingIntervalMinutes" not in str(lookback),
          f"{label}: the lookback must not scale with PollingIntervalMinutes (a failed write drops out of reach)")

    # Synced incidents are dropped before the Foreach, so a wide window stays cheap.
    flt = actions.get("Filter_Unsynced") or {}
    where = (flt.get("inputs") or {}).get("where", "")
    check(flt.get("type") == "Query" and (flt.get("inputs") or {}).get("from") == "@variables('closed_incidents')",
          f"{label}: Filter_Unsynced must be a Query over closed_incidents")
    check("'Synced'" in where and "not(" in where,
          f"{label}: Filter_Unsynced must keep only incidents without the Synced label")
    # A caught page failure can leave the Until Failed/TimedOut; the partial list must still be
    # processed and Check_Closed_Query_Failed must still run, so Filter_Unsynced follows all three.
    check(set(flt.get("runAfter", {}).get("Pagination_Loop_Closed", [])) == {"Succeeded", "Failed", "TimedOut"}
          and list(flt.get("runAfter", {})) == ["Pagination_Loop_Closed"],
          f"{label}: Filter_Unsynced must run after Pagination_Loop_Closed Succeeded, Failed and TimedOut")
    foreach = actions["For_Each_Incident"]
    check(foreach.get("foreach") == "@body('Filter_Unsynced')",
          f"{label}: For_Each_Incident must iterate the filtered list, got {foreach.get('foreach')!r}")
    check(foreach.get("runAfter") == {"Filter_Unsynced": ["Succeeded"]},
          f"{label}: For_Each_Incident must wait for Filter_Unsynced")

    # A failed page query must end the loop instead of repeating the page until the timeout.
    loop = actions.get("Pagination_Loop_Closed") or {}
    inner = loop.get("actions", {})
    flag = inner.get("Flag_Closed_Query_Failed") or {}
    stop = inner.get("Stop_Closed_Pagination") or {}
    check(set((flag.get("runAfter") or {}).get("Compose_New_Closed", [])) >= {"Failed", "TimedOut", "Skipped"},
          f"{label}: Flag_Closed_Query_Failed must run when the page query's follow-up is Failed/TimedOut/Skipped")
    check((flag.get("inputs") or {}).get("name") == "closed_query_failed"
          and (flag.get("inputs") or {}).get("value") is True,
          f"{label}: Flag_Closed_Query_Failed must set closed_query_failed to true")
    check((stop.get("inputs") or {}).get("name") == "closed_next_link" and (stop.get("inputs") or {}).get("value") == ""
          and "Flag_Closed_Query_Failed" in (stop.get("runAfter") or {}),
          f"{label}: Stop_Closed_Pagination must empty closed_next_link after the flag so the Until exits")
    init = actions.get("Initialize_Closed_Query_Failed") or {}
    variables = (init.get("inputs") or {}).get("variables") or [{}]
    check(variables[0].get("name") == "closed_query_failed" and variables[0].get("value") is False
          and "Initialize_Closed_Query_Failed" in (loop.get("runAfter") or {}),
          f"{label}: closed_query_failed must start false and be initialised before the loop")

    # The run must not report Succeeded when a page was lost.
    gate = actions.get("Check_Closed_Query_Failed") or {}
    terminate = ((gate.get("actions") or {}).get("Fail_Incomplete_Sync") or {})
    check(set((gate.get("runAfter") or {}).get("For_Each_Incident", [])) >= {"Succeeded", "Failed"}
          and "closed_query_failed" in json.dumps(gate.get("expression")),
          f"{label}: Check_Closed_Query_Failed must run after For_Each_Incident and read closed_query_failed")
    check(terminate.get("type") == "Terminate"
          and (terminate.get("inputs") or {}).get("runStatus") == "Failed",
          f"{label}: Fail_Incomplete_Sync must end the run Failed")

# The deployed output must state the real window, not the old 2x polling interval.
with open(TEMPLATES["Playbooks/SOCRadar-Alarm-Sync"], encoding="utf-8") as handle:
    outputs = json.load(handle).get("outputs", {})
check(outputs.get("lookbackWindow", {}).get("value") == f"{MIN_WINDOW_HOURS} hours",
      f"Sync playbook output lookbackWindow must say '{MIN_WINDOW_HOURS} hours', got {outputs.get('lookbackWindow')!r}")

if failures:
    for message in failures:
        print("FAIL " + message)
    sys.exit(1)
print(f"Sync window and page-failure handling verified in {checks} assertions.")
