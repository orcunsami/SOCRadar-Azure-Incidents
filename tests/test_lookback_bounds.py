#!/usr/bin/env python3
"""InitialLookbackMinutes is bounded 10..10080, and 10080 is the window ceiling the import enforces.

The form takes the first-run window. ARM rejects a value above the template's maxValue before
anything is created (measured: 21600 fails validation), so the bound has to be the same 7 days
the Determine_Lookback expression clamps to; a looser bound would promise a window the import
never reads. Checked in the combined template and in the standalone import playbook.

Run:  python3 tests/test_lookback_bounds.py
"""
import json
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FILES = ["azuredeploy.json", os.path.join("Playbooks", "SOCRadar-Alarm-Import", "azuredeploy.json")]
failures = []
checks = 0


def check(ok, message):
    global checks
    checks += 1
    if not ok:
        failures.append(message)


for rel in FILES:
    with open(os.path.join(REPO, rel), encoding="utf-8") as handle:
        template = json.load(handle)
    param = template["parameters"]["InitialLookbackMinutes"]
    check(param.get("minValue") == 10, f"{rel}: InitialLookbackMinutes minValue must be 10, found {param.get('minValue')}")
    check(param.get("maxValue") == 10080, f"{rel}: InitialLookbackMinutes maxValue must be 10080, found {param.get('maxValue')}")
    check(10 <= param.get("defaultValue", 0) <= 10080, f"{rel}: the default must sit inside the bounds")
    workflow = next(r for r in template["resources"] if r["type"] == "Microsoft.Logic/workflows")
    expr = workflow["properties"]["definition"]["actions"]["Determine_Lookback"]["inputs"]
    check(", 10080))" in expr, f"{rel}: Determine_Lookback must clamp the window to 10080 minutes")

for failure in failures:
    print(f"FAIL: {failure}")
if failures:
    sys.exit(1)
print(f"Lookback bounds: 10..10080 and the 10080 clamp hold in both templates ({checks} checks).")
