#!/usr/bin/env python3
"""Break the alert-backed mode on purpose and prove tests/test_alert_backed_mode.py notices.

Each mutation is applied to both hand-maintained copies (azuredeploy.json and the standalone
playbook) so the drift check stays quiet and only the behavioural check can catch it. A
mutation that survives is BLIND and the run exits non-zero. Bytecode is disabled for the
child runs (EXP-AZURE-0179).

    python3 tests/mutate_alert_backed.py
"""
import json
import os
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT = os.path.join(REPO, "azuredeploy.json")
IMPORT = os.path.join(REPO, "Playbooks", "SOCRadar-Alarm-Import", "azuredeploy.json")
SYNC = os.path.join(REPO, "Playbooks", "SOCRadar-Alarm-Sync", "azuredeploy.json")
TEST = os.path.join(REPO, "tests", "test_alert_backed_mode.py")


def find(actions, name):
    for key, value in actions.items():
        if key == name:
            return value
        for sub in ("actions", "else"):
            if isinstance(value, dict) and sub in value:
                inner = value[sub] if sub == "actions" else value[sub].get("actions", {})
                hit = find(inner, name)
                if hit is not None:
                    return hit
    return None


def workflow(template, kind):
    for resource in template["resources"]:
        if resource["type"] != "Microsoft.Logic/workflows":
            continue
        actions = resource["properties"]["definition"]["actions"]
        if (kind == "import" and "Pagination_Loop" in actions) or (kind == "sync" and "For_Each_Incident" in actions):
            return resource


def rule(template):
    nested = next(r for r in template["resources"] if r.get("name") == "deploy-alert-backed-rule")
    inner = nested["properties"]["template"]["resources"]
    return next(r for r in inner if r["type"].endswith("/alertRules")), \
        next(r for r in inner if r["type"].endswith("/automationRules"))


def m_timegenerated_window(t):
    r, _ = rule(t)
    r["properties"]["query"] = r["properties"]["query"].replace("ingestion_time() > ago(10m)", "TimeGenerated > ago(10m)")


def m_closed_alarms_alert(t):
    r, _ = rule(t)
    r["properties"]["query"] = r["properties"]["query"].replace('| where toupper(Status) == "OPEN"\n', "")


def m_take_150(t):
    r, _ = rule(t)
    r["properties"]["query"] = r["properties"]["query"].replace("| take 149", "| take 150")


def m_group_by_nothing(t):
    r, _ = rule(t)
    r["properties"]["incidentConfiguration"]["groupingConfiguration"]["groupByEntities"] = []


def m_reopen_closed(t):
    r, _ = rule(t)
    r["properties"]["incidentConfiguration"]["groupingConfiguration"]["reopenClosedIncident"] = True


def m_automation_label(t):
    _, a = rule(t)
    a["properties"]["actions"][0]["actionConfiguration"]["labels"] = [{"labelName": "SOCRadar-AlertBacked"}]


def m_loop_parallel(t):
    actions = workflow(t, "import")["properties"]["definition"]["actions"]
    find(actions, "For_Each_Alarm_AlertBacked")["runtimeConfiguration"]["concurrency"]["repetitions"] = 5


def m_checkpoint_advances_when_capped(t):
    actions = workflow(t, "import")["properties"]["definition"]["actions"]
    find(actions, "Write_Checkpoint")["inputs"]["body"]["LastRunUtc"] = "@{outputs('Capture_Run_Start')}"


def m_cap_never_set(t):
    actions = workflow(t, "import")["properties"]["definition"]["actions"]
    find(actions, "Set_Capped")["inputs"]["value"] = False


def m_marker_read_failure_ignored(t):
    actions = workflow(t, "import")["properties"]["definition"]["actions"]
    verify = find(actions, "Verify_Import_Complete")
    verify["expression"]["and"] = [c for c in verify["expression"]["and"] if "marker_read_failed" not in json.dumps(c)]


def m_direct_loop_ungated(t):
    actions = workflow(t, "import")["properties"]["definition"]["actions"]
    should = find(actions, "Check_If_Should_Import")
    should["expression"] = {"or": should["expression"]["and"][0]["or"]}


def m_marker_written_before_ingest(t):
    actions = workflow(t, "import")["properties"]["definition"]["actions"]
    find(actions, "Write_Seen_Marker")["runAfter"] = {}


def m_cap_formula_loosened(t):
    workflow(t, "import")["properties"]["parameters"]["AlertBackedMaxNewPerRun"]["value"] = "[div(48, div(10, parameters('PollingIntervalMinutes')))]"


def m_rule_deployment_unconditional(t):
    nested = next(r for r in t["resources"] if r.get("name") == "deploy-alert-backed-rule")
    nested["condition"] = "[true()]"


def m_sync_reads_unresolved_id(t):
    actions = workflow(t, "sync")["properties"]["definition"]["actions"]
    update = find(actions, "Update_SOCRadar_Status")
    update["inputs"]["body"] = json.loads(json.dumps(update["inputs"]["body"]).replace("Resolve_Alarm_ID", "Extract_Alarm_ID"))


def m_sync_skips_resolver(t):
    actions = workflow(t, "sync")["properties"]["definition"]["actions"]
    find(actions, "Check_If_Closed_And_Not_Synced")["runAfter"] = {"Check_Has_Synced_Tag": ["Succeeded"]}


def m_sync_reads_any_url(t):
    actions = workflow(t, "sync")["properties"]["definition"]["actions"]
    find(actions, "Filter_Alarm_Url_Entities")["inputs"]["where"] = "@equals(item()?['kind'], 'Url')"


MUTATIONS = [
    ("rule windows on TimeGenerated", (ROOT, IMPORT), m_timegenerated_window),
    ("closed alarms become incidents", (ROOT, IMPORT), m_closed_alarms_alert),
    ("rule takes 150 rows", (ROOT, IMPORT), m_take_150),
    ("no grouping entity", (ROOT, IMPORT), m_group_by_nothing),
    ("duplicate alert reopens closed", (ROOT, IMPORT), m_reopen_closed),
    ("automation label renamed", (ROOT, IMPORT), m_automation_label),
    ("alert-backed loop parallel", (ROOT, IMPORT), m_loop_parallel),
    ("checkpoint advances when capped", (ROOT, IMPORT), m_checkpoint_advances_when_capped),
    ("cap never set", (ROOT, IMPORT), m_cap_never_set),
    ("marker read failure ignored", (ROOT, IMPORT), m_marker_read_failure_ignored),
    ("Direct loop runs in AlertBacked", (ROOT, IMPORT), m_direct_loop_ungated),
    ("marker written before ingest", (ROOT, IMPORT), m_marker_written_before_ingest),
    ("cap formula loosened", (ROOT, IMPORT), m_cap_formula_loosened),
    ("rule deployed in Direct mode", (ROOT, IMPORT), m_rule_deployment_unconditional),
    ("Sync sends unresolved id", (ROOT, SYNC), m_sync_reads_unresolved_id),
    ("Sync skips the resolver", (ROOT, SYNC), m_sync_skips_resolver),
    ("Sync reads any URL entity", (ROOT, SYNC), m_sync_reads_any_url),
]


def main():
    blind = []
    for name, paths, mutate in MUTATIONS:
        originals = {p: open(p, encoding="utf-8").read() for p in paths}
        try:
            for p in paths:
                template = json.loads(originals[p])
                mutate(template)
                with open(p, "w", encoding="utf-8") as handle:
                    handle.write(json.dumps(template, indent=4, ensure_ascii=False))
            try:
                result = subprocess.run([sys.executable, TEST], cwd=REPO, capture_output=True, text=True,
                                        timeout=60, env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
                rc = result.returncode
            except subprocess.TimeoutExpired:
                rc = 124
        finally:
            for p, text in originals.items():
                with open(p, "w", encoding="utf-8") as handle:
                    handle.write(text)
        if rc == 0:
            print("BLIND  %-34s test still passed" % name)
            blind.append(name)
        else:
            print("caught %-34s" % name)
    print("\nblind: %d of %d" % (len(blind), len(MUTATIONS)))
    return 1 if blind else 0


if __name__ == "__main__":
    sys.exit(main())
