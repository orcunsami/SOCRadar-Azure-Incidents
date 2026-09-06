#!/usr/bin/env python3
"""Guard the severity write-back against the failure in EXP-AZURE-0172.

Microsoft Sentinel's severity scale stops at High. SOCRadar's has CRITICAL above it.
Sync used to push the Microsoft Sentinel severity back to SOCRadar on every close with
nothing gating it, so closing a SOCRadar CRITICAL alarm in Microsoft Sentinel lowered it
to HIGH permanently. Measured live on 2026-09-04: the write succeeds and cannot be undone.

Two layers now stop that: the SyncSeverity parameter (on by default, can be turned off) and, when it is on,
a rank comparison that only ever raises a severity. This test pins both, in the one-click
template and in the standalone playbook, and pins the decision table itself.

Run:  python3 tests/test_severity_sync_logic.py
"""

import json
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT = os.path.join(REPO, "azuredeploy.json")
SYNC = os.path.join(REPO, "Playbooks", "SOCRadar-Alarm-Sync", "azuredeploy.json")
IMPORT = os.path.join(REPO, "Playbooks", "SOCRadar-Alarm-Import", "azuredeploy.json")

LABEL_PREFIX = "SOCRadar-Severity-"
# Rank 0 means "no usable SOCRadar severity", which is what stops the write. INFO has to
# occupy a rank of its own: it is the most common level the feed produces (20 of 35 alarms in
# the last 7 days, measured 2026-09-05), and while it sat at 0 an INFO alarm could never have
# its severity raised, which made the whole feature inert for most of the feed.
SOCRADAR_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1, "": 0}
# Microsoft Sentinel's Informational stays at 0 on purpose: it is never written back, because
# SOCRadar's own lowest level is INFO and lowering is not what this feature does.
SENTINEL_RANK = {"High": 4, "Medium": 3, "Low": 2, "Informational": 0}

failures = []


def check(condition, message):
    if not condition:
        failures.append(message)


def load(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def workflows(template, needle=None):
    out = []
    for resource in template.get("resources", []):
        if resource.get("type") != "Microsoft.Logic/workflows":
            continue
        if needle is None or needle in str(resource.get("name", "")):
            out.append(resource)
    return out


def flatten(actions, prefix=""):
    found = {}
    for name, body in (actions or {}).items():
        path = prefix + name
        found[path] = body
        if isinstance(body, dict):
            if isinstance(body.get("actions"), dict):
                found.update(flatten(body["actions"], path + "/"))
            branch = body.get("else")
            if isinstance(branch, dict) and isinstance(branch.get("actions"), dict):
                found.update(flatten(branch["actions"], path + "/"))
    return found


def sole(paths, name, label):
    hits = [p for p in paths if p.split("/")[-1] == name]
    if len(hits) != 1:
        failures.append("%s: expected exactly one %s, found %d" % (label, name, len(hits)))
        return None
    return hits[0]


def would_write(socradar_severity, sentinel_severity):
    """The decision the template's two Compose ranks plus Check_Not_Lowering encode."""
    socradar = SOCRADAR_RANK[socradar_severity]
    sentinel = SENTINEL_RANK[sentinel_severity]
    return socradar > 0 and sentinel > socradar


def check_sync(template, label, needle=None):
    found = workflows(template, needle)
    if len(found) != 1:
        failures.append("%s: expected one sync workflow, found %d" % (label, len(found)))
        return
    workflow = found[0]

    parameters = workflow["properties"]["definition"].get("parameters", {})
    check("SyncSeverity" in parameters, "%s: workflow parameter SyncSeverity missing" % label)
    if "SyncSeverity" in parameters:
        check(parameters["SyncSeverity"].get("defaultValue") is True,
              "%s: workflow SyncSeverity must default to true" % label)
    passed = workflow["properties"].get("parameters", {})
    check(passed.get("SyncSeverity") == {"value": "[parameters('SyncSeverity')]"},
          "%s: SyncSeverity is not passed from the ARM parameter" % label)

    actions = flatten(workflow["properties"]["definition"]["actions"])
    gate = sole(actions, "Check_Severity_Sync_Enabled", label)
    write = sole(actions, "Update_SOCRadar_Severity", label)
    guard = sole(actions, "Check_Not_Lowering", label)
    if not (gate and write and guard):
        return

    check(guard.startswith(gate + "/"), "%s: Check_Not_Lowering is not inside the SyncSeverity gate" % label)
    check(write.startswith(guard + "/"), "%s: the severity write is not inside Check_Not_Lowering" % label)
    check(actions[gate]["expression"] == {"and": [{"equals": ["@parameters('SyncSeverity')", True]}]},
          "%s: the SyncSeverity gate expression changed" % label)
    check(actions[guard]["expression"] == {"and": [
        {"greater": ["@outputs('Rank_SOCRadar_Severity')", 0]},
        {"greater": ["@outputs('Rank_Sentinel_Severity')", "@outputs('Rank_SOCRadar_Severity')"]},
    ]}, "%s: Check_Not_Lowering no longer requires a known SOCRadar rank and a strictly higher one" % label)

    extract = actions.get(gate + "/Extract_SOCRadar_Severity", {}).get("inputs", "")
    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        check(LABEL_PREFIX + severity in extract,
              "%s: Extract_SOCRadar_Severity does not look for %s%s" % (label, LABEL_PREFIX, severity))

    socradar_ranks = actions.get(gate + "/Rank_SOCRadar_Severity", {}).get("inputs", "")
    for severity, rank in sorted(SOCRADAR_RANK.items()):
        if not severity:
            continue
        check("'%s'), %d" % (severity, rank) in socradar_ranks,
              "%s: SOCRadar rank for %s is not %d" % (label, severity, rank))
    sentinel_ranks = actions.get(gate + "/Rank_Sentinel_Severity", {}).get("inputs", "")
    for severity, rank in sorted(SENTINEL_RANK.items()):
        if not rank:
            continue
        check("'%s'), %d" % (severity, rank) in sentinel_ranks,
              "%s: Microsoft Sentinel rank for %s is not %d" % (label, severity, rank))
    # The fallback matters as much as the named levels. Anything unrecognised -- and
    # Informational, which is deliberately unnamed -- has to land on 0, or a severity nobody
    # mapped starts comparing as if it were real.
    check(sentinel_ranks.rstrip().endswith(", 0)))"),
          "%s: the Microsoft Sentinel rank does not fall back to 0: %s"
          % (label, sentinel_ranks[-40:]))
    check(socradar_ranks.rstrip().endswith(", 0)))))"),
          "%s: the SOCRadar rank does not fall back to 0: %s" % (label, socradar_ranks[-40:]))

    written = sole(actions, "Check_Severity_Write_Succeeded", label)
    if written:
        check(actions[written]["expression"] == {"and": [
            {"equals": ["@coalesce(body('Update_SOCRadar_Severity')?['is_success'], false)", True]}
        ]}, "%s: the severity response is no longer judged by is_success" % label)
        check("Log_Severity_Write_Failed" in actions[written].get("else", {}).get("actions", {}),
              "%s: a rejected severity write is not recorded" % label)

    check(template["parameters"]["SyncSeverity"]["defaultValue"] is True,
          "%s: the ARM parameter SyncSeverity must default to true" % label)
    description = template["parameters"]["SyncSeverity"]["metadata"]["description"]
    check("Microsoft Sentinel" in description and "Critical" in description,
          "%s: the SyncSeverity description must explain the Critical limitation" % label)


def check_import(template, label, needle=None):
    found = workflows(template, needle)
    if len(found) != 1:
        failures.append("%s: expected one import workflow, found %d" % (label, len(found)))
        return
    actions = flatten(found[0]["properties"]["definition"]["actions"])
    # Two actions build the incident's labels, one per creation path, and BOTH have to carry
    # the severity. Build_Labels feeds the closed-incident REST call, which only runs when
    # ImportAllStatuses is on. Build_Tags feeds the managed connector, which is what creates
    # every incident on the default OPEN-only path. Putting the label in Build_Labels alone
    # was measured live on 2026-09-04: three real incidents were created carrying
    # SOCRadar / Domain / Impersonating Domain and no severity label at all, so the whole
    # EXP-0172 protection was inert for the default configuration.
    for action_name, path in (("Build_Labels", "the closed-incident REST call"),
                              ("Build_Tags", "the managed connector, used on the default path")):
        build = sole(actions, action_name, label)
        if not build:
            continue
        expression = actions[build]["inputs"]
        check(LABEL_PREFIX in expression,
              "%s: %s no longer writes the %s label, so an incident created through %s carries "
              "no SOCRadar severity and Sync will never sync one"
              % (label, action_name, LABEL_PREFIX, path))
        check("alarm_risk_level" in expression,
              "%s: the severity label in %s is not built from alarm_risk_level" % (label, action_name))

    # An alarm that is already closed in SOCRadar is imported as a closed incident, and Sync
    # picks up every closed SOCRadar incident that has no Synced label. Without one, Sync writes
    # a status back for a closure that came from SOCRadar in the first place - and an alarm whose
    # status maps to Undetermined (INVESTIGATING, for one) would be written back as RESOLVED.
    # Build_Labels is the closed path only, so the label belongs there and nowhere else: putting
    # it in Build_Tags would make every OPEN incident unsyncable.
    closed = sole(actions, "Build_Labels", label)
    active = sole(actions, "Build_Tags", label)
    if closed:
        check('"labelName": "Synced"' in actions[closed]["inputs"],
              "%s: Build_Labels does not mark the incident Synced, so Sync will write a status "
              "back to SOCRadar for a closure SOCRadar itself reported" % label)
    if active:
        check("Synced" not in actions[active]["inputs"],
              "%s: Build_Tags marks the incident Synced - every imported OPEN incident would then "
              "be invisible to Sync and no closure would ever reach SOCRadar" % label)


def check_decision_table():
    """The table is the point of the change. Every row is a customer outcome."""
    cases = [
        ("CRITICAL", "High", False, "the EXP-0172 bug: a CRITICAL alarm closed as High must not be lowered"),
        ("CRITICAL", "Medium", False, "a CRITICAL alarm must not be lowered to Medium"),
        ("CRITICAL", "Low", False, "a CRITICAL alarm must not be lowered to Low"),
        ("HIGH", "Medium", False, "no lowering"),
        ("MEDIUM", "Low", False, "no lowering"),
        ("HIGH", "High", False, "equal severity is not worth a call"),
        ("LOW", "High", True, "an analyst raising a Low alarm to High is the point of the feature"),
        ("LOW", "Medium", True, "raising Low to Medium is allowed"),
        ("MEDIUM", "High", True, "raising Medium to High is allowed"),
        ("", "High", False, "an incident with no SOCRadar severity label is left alone"),
        ("LOW", "Informational", False, "Informational is never written back"),
        ("CRITICAL", "Informational", False, "Informational must never reach the API"),
        ("INFO", "Low", True, "INFO is the most common level in the feed and must be raisable"),
        ("INFO", "Medium", True, "raising INFO to Medium is allowed"),
        ("INFO", "High", True, "raising INFO to High is allowed"),
        ("INFO", "Informational", False, "equal in meaning, and Informational is never sent"),
        ("LOW", "Low", False, "equal severity is not worth a call"),
    ]
    for socradar, sentinel, expected, why in cases:
        actual = would_write(socradar, sentinel)
        check(actual == expected,
              "decision table: SOCRadar=%r Sentinel=%r expected write=%s got %s (%s)"
              % (socradar or "no label", sentinel, expected, actual, why))


def main():
    root = load(ROOT)
    check_sync(root, "root", "Sync")
    check_sync(load(SYNC), "standalone")
    check_import(root, "root import", "Import")
    check_import(load(IMPORT), "standalone import")
    check_decision_table()

    if failures:
        print("SEVERITY SYNC CHECK FAILED\n")
        for item in failures:
            print("  - " + item)
        print("\n%d problem(s)." % len(failures))
        return 1
    print("Severity write-back is gated, cannot lower a SOCRadar severity, and is judged by is_success.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
