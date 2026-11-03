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


def m_default_direct(t):
    t["parameters"]["IncidentMode"]["defaultValue"] = "Direct"


def m_timegenerated_window(t):
    r, _ = rule(t)
    r["properties"]["query"] = r["properties"]["query"].replace("ingestion_time() > ago(1d)", "TimeGenerated > ago(1d)")


def m_closed_alarms_alert(t):
    r, _ = rule(t)
    r["properties"]["query"] = r["properties"]["query"].replace('| where toupper(Status) == "OPEN"\n', "")


def m_take_150(t):
    r, _ = rule(t)
    r["properties"]["query"] = r["properties"]["query"].replace("| take 149", "| take 150")


def m_group_by_nothing(t):
    # Grouping moved from the URL entity to the AlarmId custom detail (task_azure_0098:
    # once IoC URL entities exist, two unrelated alarms could share one and wrongly merge).
    # Mutate by reverting to the old, now-wrong state.
    r, _ = rule(t)
    gc = r["properties"]["incidentConfiguration"]["groupingConfiguration"]
    gc["groupByEntities"] = ["URL"]
    gc["groupByCustomDetails"] = []


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


def m_rule_description_plain(t):
    r, _ = rule(t)
    r["properties"]["alertDetailsOverride"]["alertDescriptionFormat"] = "{{AlarmText}}"


def m_rule_marker_renamed(t):
    r, _ = rule(t)
    r["properties"]["query"] = r["properties"]["query"].replace("SOCRadar severity: ", "Severity: ")


def m_rank_reads_labels_only(t):
    actions = workflow(t, "sync")["properties"]["definition"]["actions"]
    rank = find(actions, "Rank_SOCRadar_Severity")
    rank["inputs"] = rank["inputs"].replace("Resolve_SOCRadar_Severity", "Extract_SOCRadar_Severity")


def m_description_skips_critical(t):
    actions = workflow(t, "sync")["properties"]["definition"]["actions"]
    reader = find(actions, "Severity_From_Description")
    reader["inputs"] = reader["inputs"].replace("'SOCRadar severity: CRITICAL'), 'CRITICAL'", "'SOCRadar severity: CRITICAL'), 'HIGH'")


def m_resolve_prefers_description(t):
    actions = workflow(t, "sync")["properties"]["definition"]["actions"]
    find(actions, "Resolve_SOCRadar_Severity")["inputs"] = (
        "@if(empty(outputs('Severity_From_Description')), outputs('Extract_SOCRadar_Severity'), "
        "outputs('Severity_From_Description'))")


def m_sync_reads_any_url(t):
    actions = workflow(t, "sync")["properties"]["definition"]["actions"]
    find(actions, "Filter_Alarm_Url_Entities")["inputs"]["where"] = "@equals(item()?['kind'], 'Url')"


def m_entity_mapping_dropped(t):
    r, _ = rule(t)
    r["properties"]["entityMappings"] = r["properties"]["entityMappings"][:-1]


def m_ioc_enrichment_hard_fail(t):
    actions = workflow(t, "import")["properties"]["definition"]["actions"]
    find(actions, "Parse_AlertBacked_IoC_Arrays")["runAfter"] = {"Run_AlertBacked_IoC_Regex_Query": ["Succeeded"]}


def m_ioc_column_wrong_index(t):
    actions = workflow(t, "import")["properties"]["definition"]["actions"]
    find(actions, "Ingest_Alarm_Row")["inputs"]["body"][0]["IoCIp1"] = (
        "@{coalesce(outputs('Parse_AlertBacked_IoC_Arrays')?['ips']?[1], '')}")


def m_description_pipe_table(t):
    r, _ = rule(t)
    q = r["properties"]["query"]
    r["properties"]["query"] = q.replace('strcat("Content:\\n\\n", strcat_array(array_slice(ContentRows, 0, 5), "\\n\\n"))',
                                         'strcat("Content:\\n\\n| Field | Value |\\n|---|---|\\n", strcat_array(ContentRows, "\\n"))')


def m_description_link_glued(t):
    r, _ = rule(t)
    r["properties"]["query"] = r["properties"]["query"].replace('strcat("\\n\\nView in SOCRadar: "', 'strcat("View in SOCRadar: "')


def m_no_alert_dedup(t):
    r, _ = rule(t)
    r["properties"]["query"] = r["properties"]["query"].replace("| join kind=leftanti Alerted on $left.AlarmId == $right.AlertedAlarmId\n", "")


def m_dedup_flat_custom_details(t):
    r, _ = rule(t)
    r["properties"]["query"] = r["properties"]["query"].replace(
        "tostring(parse_json(tostring(parse_json(tostring(ExtendedProperties))['Custom Details'])).AlarmId[0])",
        "tostring(parse_json(tostring(ExtendedProperties)).AlarmId)")


def m_no_holdback(t):
    r, _ = rule(t)
    r["properties"]["query"] = r["properties"]["query"].replace("| where ingestion_time() < ago(12m)\n", "")


def m_five_minute_runs(t):
    r, _ = rule(t)
    r["properties"]["queryFrequency"] = "PT5M"


def m_description_html_escape(t):
    r, _ = rule(t)
    q = r["properties"]["query"]
    r["properties"]["query"] = q.replace('| extend DetailsMarkdown = trim(@"\\s", replace_string(replace_string(substring(AlarmText, 0, 1500), "\\r", ""), "\\n", " "))',
                                         '| extend DetailsMarkdown = trim(@"\\s", replace_string(replace_string(replace_string(replace_string(substring(AlarmText, 0, 1500), "\\r", ""), "\\n", " "), "<", "&lt;"), "*", "\\\\*"))')


def m_dns_from_regex_domain(t):
    r, _ = rule(t)
    for mapping in r["properties"]["entityMappings"]:
        for fm in mapping["fieldMappings"]:
            if fm["columnName"] == "SuspiciousDomain":
                fm["columnName"] = "IoCDomain1"


def m_content_uncapped(t):
    r, _ = rule(t)
    r["properties"]["query"] = r["properties"]["query"].replace("array_slice(ContentRows, 0, 5)", "ContentRows")


def m_phishing_domain_not_ingested(t):
    for res in t["resources"]:
        if res["type"] == "Microsoft.Insights/dataCollectionRules" and "AlarmsDcrName" in res["name"]:
            for flow in res["properties"]["dataFlows"]:
                flow["transformKql"] = flow["transformKql"].replace(", 'phishing_domain', AlarmPayload['content']['phishing_domain']", "")


def m_monitored_asset_dropped(t):
    r, _ = rule(t)
    r["properties"]["customDetails"].pop("MonitoredAsset", None)


def m_domain_from_payload_only(t):
    r, _ = rule(t)
    q = r["properties"]["query"]
    r["properties"]["query"] = q.replace('extract(@"Phishing Domain:\\s*([^\\s,;]+)", 1, AlarmText)', '""')


def m_content_domain_from_payload(t):
    r, _ = rule(t)
    r["properties"]["query"] = r["properties"]["query"].replace("pack('Suspicious Domain', SuspiciousDomain,", "pack('Suspicious Domain', AlarmPayload['phishing_domain'],")


def m_domain_regex_greedy(t):
    r, _ = rule(t)
    r["properties"]["query"] = r["properties"]["query"].replace('Phishing Domain:\\s*([^\\s,;]+)', 'Phishing Domain:\\s*(\\S+)')


MUTATIONS = [
    ("IncidentMode defaults to Direct again", (ROOT, IMPORT), m_default_direct),
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
    ("rule description drops the marker", (ROOT, IMPORT), m_rule_description_plain),
    ("rule marker text renamed", (ROOT, IMPORT), m_rule_marker_renamed),
    ("rank reads labels only", (ROOT, SYNC), m_rank_reads_labels_only),
    ("description reader maps CRITICAL wrong", (ROOT, SYNC), m_description_skips_critical),
    ("resolver prefers description", (ROOT, SYNC), m_resolve_prefers_description),
    ("entity mapping dropped", (ROOT, IMPORT), m_entity_mapping_dropped),
    ("IoC enrichment hard-fails ingest", (ROOT, IMPORT), m_ioc_enrichment_hard_fail),
    ("description goes back to a pipe table", (ROOT, IMPORT), m_description_pipe_table),
    ("link glued to severity line", (ROOT, IMPORT), m_description_link_glued),
    ("rule alerts an alarm twice", (ROOT, IMPORT), m_no_alert_dedup),
    ("rows are not held back before alerting", (ROOT, IMPORT), m_no_holdback),
    ("description escapes markdown again", (ROOT, IMPORT), m_description_html_escape),
    ("DNS entity is the regex-found domain again", (ROOT, IMPORT), m_dns_from_regex_domain),
    ("Content block lists every field", (ROOT, IMPORT), m_content_uncapped),
    ("Content domain read from the payload key", (ROOT, IMPORT), m_content_domain_from_payload),
    ("domain no longer read from the alarm text", (ROOT, IMPORT), m_domain_from_payload_only),
    ("phishing domain regex takes a comma list whole", (ROOT, IMPORT), m_domain_regex_greedy),
    ("phishing domain not ingested", (ROOT,), m_phishing_domain_not_ingested),
    ("monitored asset dropped from custom details", (ROOT, IMPORT), m_monitored_asset_dropped),
    ("rule runs every 5 minutes again", (ROOT, IMPORT), m_five_minute_runs),
    ("alerted-AlarmId read uses the flat shape", (ROOT, IMPORT), m_dedup_flat_custom_details),
    ("IoC column reads wrong index", (ROOT, IMPORT), m_ioc_column_wrong_index),
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
