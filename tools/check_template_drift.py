#!/usr/bin/env python3
"""Fail if the standalone Playbooks/ templates drift away from azuredeploy.json.

Ported from Radargoger/SOCRadar-Azure-Incidents (commit b2e58a3) and adapted to this
repo's action names and template set. The one-click template and the standalone
templates hold two hand-maintained copies of the same logic; they can silently drift
apart. This check compares the expressions that carry the behaviour and exits
non-zero when they stop matching.

Adaptation notes (this repo differs from the upstream repo this was ported from):
  - This repo's sync playbook has no named "Check_SOCRadar_Write_Succeeded" condition
    action; Add_Synced_Tag is instead gated purely by its runAfter dependency on
    Update_SOCRadar_Status ("Succeeded"). The guard check below compares that
    dependency (and the containing If-action) between root and standalone instead of
    a named condition action that does not exist here.
  - This repo has a 7th template, Playbooks/SOCRadar-IOC-Enrichment/azuredeploy.json,
    with no counterpart in azuredeploy.json (it was never merged into the one-click
    template). It is intentionally excluded from the root-vs-standalone comparisons
    below -- there is nothing in root to diff it against. It is still covered by the
    JSON-parse and PT1H sweeps in the workflow / this script.

Run:  python3 tools/check_template_drift.py
"""

import json
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT = os.path.join(REPO, "azuredeploy.json")
IMPORT = os.path.join(REPO, "Playbooks", "SOCRadar-Alarm-Import", "azuredeploy.json")
SYNC = os.path.join(REPO, "Playbooks", "SOCRadar-Alarm-Sync", "azuredeploy.json")
ALARMS_INFRA = os.path.join(REPO, "Playbooks", "SOCRadar-Alarms-Infrastructure", "azuredeploy.json")
AUDIT_INFRA = os.path.join(REPO, "Playbooks", "SOCRadar-Audit-Infrastructure", "azuredeploy.json")

# Every azuredeploy.json in the repo, including the ones not compared below
# (IOC-Enrichment has no root counterpart, Workbook has no workflow/DCR to drift).
ALL_TEMPLATES = [ROOT, IMPORT, SYNC, ALARMS_INFRA, AUDIT_INFRA,
                  os.path.join(REPO, "Playbooks", "SOCRadar-IOC-Enrichment", "azuredeploy.json"),
                  os.path.join(REPO, "Playbooks", "SOCRadar-Workbook", "azuredeploy.json")]


def load(path):
    with open(path) as fh:
        return json.load(fh)


def walk_actions(actions, prefix=""):
    found = {}
    for name, body in actions.items():
        found[prefix + name] = body
        if "actions" in body:
            found.update(walk_actions(body["actions"], prefix + name + "/"))
        branch = body.get("else")
        if isinstance(branch, dict) and "actions" in branch:
            found.update(walk_actions(branch["actions"], prefix + name + "/else/"))
    return found


def workflow_actions(template, want_sync=None):
    """Collect actions from the workflows in a template.

    want_sync None -> every workflow; True -> only the sync playbook; False -> only import.
    The sync playbook is the one that writes back to SOCRadar.
    """
    collected = {}
    for resource in template.get("resources", []):
        if resource.get("type") != "Microsoft.Logic/workflows":
            continue
        actions = walk_actions(resource["properties"]["definition"]["actions"])
        is_sync = any(k.split("/")[-1] == "Update_SOCRadar_Status" for k in actions)
        if want_sync is None or is_sync == want_sync:
            collected.update(actions)
    return collected


def action_field(actions, name, field):
    for key, body in actions.items():
        if key.split("/")[-1] == name:
            value = body.get(field)
            if isinstance(value, str):
                return value
            return json.dumps(value, sort_keys=True)
    return None


def request_body(actions, name):
    for key, body in actions.items():
        if key.split("/")[-1] == name:
            inputs = body.get("inputs") or {}
            return json.dumps(inputs.get("body"), sort_keys=True)
    return None


def run_after(actions, name):
    for key, body in actions.items():
        if key.split("/")[-1] == name:
            return json.dumps(body.get("runAfter"), sort_keys=True)
    return None


def transforms(template):
    out = []
    for resource in template.get("resources", []):
        if resource.get("type") == "Microsoft.Insights/dataCollectionRules":
            for flow in resource["properties"].get("dataFlows", []):
                out.append(flow.get("transformKql"))
    return out


def until_loops(template):
    """Yield (workflow_action_path, until_body) for every Until loop in a template."""
    for resource in template.get("resources", []):
        if resource.get("type") != "Microsoft.Logic/workflows":
            continue
        for path, body in walk_actions(resource["properties"]["definition"]["actions"]).items():
            if body.get("type") == "Until":
                yield path, body


def stalled_progress(until_body):
    """Names of loop actions that a single failed Foreach item would leave Skipped.

    A Foreach reports Failed when any one of its items fails, which is normal when
    the items are independent records. An action that advances the loop must not
    hang off that status, or the loop repeats the same work until it times out.
    See EXP-AZURE-0136 and EXP-AZURE-0156.
    """
    inner = until_body.get("actions", {})
    foreaches = {name for name, body in inner.items() if body.get("type") == "Foreach"}
    stalled = []
    for name, body in inner.items():
        if body.get("type") not in ("IncrementVariable", "SetVariable"):
            continue
        for dependency, statuses in (body.get("runAfter") or {}).items():
            if dependency in foreaches and "Failed" not in statuses:
                stalled.append(f"{name} waits for {dependency} {statuses}")
    return stalled


def unbounded_result_payloads(template):
    """Request bodies that embed result(), which carries every action's inputs+outputs.

    Measured live: one such body reached 1.2 MB and Azure Monitor rejected it with
    RequestEntityTooLarge on 197 of 250 repetitions. See EXP-AZURE-0156.
    """
    offenders = []
    for resource in template.get("resources", []):
        if resource.get("type") != "Microsoft.Logic/workflows":
            continue
        for path, body in walk_actions(resource["properties"]["definition"]["actions"]).items():
            if body.get("type") != "Http":
                continue
            payload = json.dumps((body.get("inputs") or {}).get("body"))
            if "result(" in payload:
                offenders.append(path)
    return offenders


def main():
    root = load(ROOT)
    root_import = workflow_actions(root, want_sync=False)
    root_sync = workflow_actions(root, want_sync=True)
    mod_import = workflow_actions(load(IMPORT))
    mod_sync = workflow_actions(load(SYNC))

    failures = []

    def compare(label, left, right):
        if left is None or right is None:
            failures.append(f"{label}: missing on one side (root={left is not None}, standalone={right is not None})")
        elif left != right:
            failures.append(f"{label}: differs\n    root:       {str(left)[:200]}\n    standalone: {str(right)[:200]}")

    # Import playbook behaviour that has drifted before.
    for name in ("Determine_Lookback", "Extract_Existing_IDs", "Calculate_Epoch_Start"):
        compare(name, action_field(root_import, name, "inputs"), action_field(mod_import, name, "inputs"))

    # Sync playbook: the write bodies must stay identical on both sides.
    for name in ("Update_SOCRadar_Status", "Update_SOCRadar_Severity"):
        compare(name + " body", request_body(root_sync, name), request_body(mod_sync, name))

    # Sync playbook guard: this repo has no named "write succeeded" condition action
    # (see module docstring). Add_Synced_Tag is gated by its runAfter dependency on
    # Update_SOCRadar_Status instead -- compare that dependency between root and
    # standalone so a change to the guard mechanism on only one side is caught.
    compare(
        "Add_Synced_Tag runAfter",
        run_after(root_sync, "Add_Synced_Tag"),
        run_after(mod_sync, "Add_Synced_Tag"),
    )

    # Add_Synced_Tag must sit inside the closed-and-not-synced guard on both sides.
    for label, actions in (("root", root_sync), ("standalone", mod_sync)):
        placed = [k for k in actions if k.split("/")[-1] == "Add_Synced_Tag"]
        if not placed:
            failures.append(f"Add_Synced_Tag: not found in the {label} sync playbook")
        elif "Check_If_Closed_And_Not_Synced" not in placed[0]:
            failures.append(f"Add_Synced_Tag: not inside the guard in the {label} sync playbook ({placed[0]})")

    # Redaction: every data collection rule in root and the standalone infrastructure
    # playbooks must keep the pack() allow-list. IOC-Enrichment and Workbook have no
    # DCR and are not part of this sweep.
    for label, path in (("root", ROOT), ("alarms infrastructure", ALARMS_INFRA), ("audit infrastructure", AUDIT_INFRA)):
        for kql in transforms(load(path)):
            if not kql or "pack(" not in kql:
                failures.append(f"transformKql in {label}: missing the pack() allow-list (value: {str(kql)[:60]})")

    # Bounded retries and loops, so a failing API call cannot stall the integration.
    # Swept across every template in the repo (not just root/import/sync) -- this is a
    # cheap regression net and IOC-Enrichment also calls an external API.
    for path in ALL_TEMPLATES:
        raw = open(path).read()
        if '"PT1H"' in raw:
            failures.append(f"{os.path.relpath(path, REPO)}: still contains a PT1H retry or loop timeout")

    # A loop must keep advancing even when one record in it fails, and no request
    # body may ship result(). Both classes broke the import live on 2026-08-18.
    for path in ALL_TEMPLATES:
        template = load(path)
        rel = os.path.relpath(path, REPO)
        for loop_path, loop in until_loops(template):
            for stall in stalled_progress(loop):
                failures.append(f"{rel}: {loop_path} cannot advance past a failed record ({stall})")
        for offender in unbounded_result_payloads(template):
            failures.append(f"{rel}: {offender} puts result() in a request body")

    if failures:
        print("TEMPLATE DRIFT DETECTED\n")
        for item in failures:
            print("  - " + item)
        print(f"\n{len(failures)} problem(s). Update the standalone templates under Playbooks/ to match azuredeploy.json.")
        return 1

    print("No drift: standalone templates match azuredeploy.json on all checked invariants.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
