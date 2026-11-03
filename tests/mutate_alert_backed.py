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


CATS = ["Phishing", "Credential", "DataLeak", "Vulnerability", "Other"]
TARGET = [0]  # which of the five rules a rule-scoped mutation hits


def rule(template):
    nested = next(r for r in template["resources"] if r.get("name") == "deploy-alert-backed-rule")
    inner = nested["properties"]["template"]["resources"]
    return [r for r in inner if r["type"].endswith("/alertRules")][TARGET[0]], \
        next(r for r in inner if r["type"].endswith("/automationRules"))


def all_rules(template):
    nested = next(r for r in template["resources"] if r.get("name") == "deploy-alert-backed-rule")
    return [r for r in nested["properties"]["template"]["resources"] if r["type"].endswith("/alertRules")]


def m_classifier_drifts_in_one_rule(t):
    r, _ = rule(t)
    r["properties"]["query"] = r["properties"]["query"].replace('"Code Repository Data Leak", ', "", 1)


def m_pair_dropped_everywhere(t):
    for r in all_rules(t):
        r["properties"]["query"] = r["properties"]["query"].replace('"PII Exposure", ', "", 1)


def m_catch_all_new_guid(t):
    t["variables"]["alertBackedRuleId"] = "[guid(variables('workspaceResourceId'), 'socradar-alert-backed-rule-2')]"


def m_automation_omits_one_rule(t):
    _, auto = rule(t)
    values = auto["properties"]["triggeringLogic"]["conditions"][0]["conditionProperties"]["propertyValues"]
    del values[-1]


def m_credential_switch_ignored(t):
    for r in all_rules(t):
        if "Credential" in r["properties"]["query"].split("| where AlarmCategory == ")[1][:14]:
            r["properties"]["enabled"] = True


def m_dcr_drops_a_key(t):
    for res in t["resources"]:
        if res["type"] == "Microsoft.Insights/dataCollectionRules" and "AlarmsDcrName" in res["name"]:
            for flow in res["properties"]["dataFlows"]:
                flow["transformKql"] = flow["transformKql"].replace(", 'computer_name', AlarmPayload['content']['computer_name']", "")


def m_title_uses_entity_column(t):
    r, _ = rule(t)
    r["properties"]["alertDetailsOverride"]["alertDisplayNameFormat"] = r["properties"]["alertDetailsOverride"]["alertDisplayNameFormat"].replace("SuspiciousDomainLabel", "SuspiciousDomain")


def m_credential_copies_secret(t):
    r, _ = rule(t)
    r["properties"]["query"] = r["properties"]["query"].replace("| extend HasMachineInfo", "| extend ExposedUser = tostring(AlarmPayload['credential_details'])\n| extend HasMachineInfo")


def m_origin_by_machine_word(t):
    r, _ = rule(t)
    r["properties"]["query"] = r["properties"]["query"].replace('case(Title has "Employee", "Employee",', 'case(Title has "Machine", "InfectedMachine", Title has "Employee", "Employee",')


def m_leak_url_any(t):
    r, _ = rule(t)
    r["properties"]["query"] = r["properties"]["query"].replace(' and LeakUrl !has "socradar.com"', "")


def m_query_too_long(t):
    r, _ = rule(t)
    r["properties"]["query"] += "\n// " + "x" * 3000


def q_replace(old, new):
    def mutate(t):
        r, _ = rule(t)
        r["properties"]["query"] = r["properties"]["query"].replace(old, new)
    mutate.__doc__ = "rule(t): replace %r" % old[:40]
    return mutate


def m_domain_regex_no_dot(t):
    r, _ = rule(t)
    r["properties"]["query"] = r["properties"]["query"].replace('Phishing Domain:\\s*([^\\s,;]+\\.[^\\s,;]+)', 'Phishing Domain:\\s*([^\\s,;]+)')


def samples(t):
    nested = next(r for r in t["resources"] if r.get("name") == "deploy-alert-backed-rule")
    return [r for r in nested["properties"]["template"]["resources"]
            if r["type"].endswith("/automationRules") and "Sample" in r["name"]]


def m_sample_unconditional(t):
    for a in samples(t):
        a.pop("condition", None)


def m_sample_adds_socradar_label(t):
    samples(t)[1]["properties"]["actions"][0]["actionConfiguration"]["labels"] = [{"labelName": "SOCRadar"}]


def m_sample_phishing_severity(t):
    samples(t)[0]["properties"]["actions"][0]["actionConfiguration"]["severity"] = "Low"


def m_sample_phishing_any_rule(t):
    conds = samples(t)[0]["properties"]["triggeringLogic"]["conditions"][0]["conditionProperties"]
    conds["propertyValues"] = conds["propertyValues"] + [conds["propertyValues"][0].replace("alertBackedPhishingRuleId", "alertBackedRuleId")]


def m_sample_key_changed(t):
    samples(t)[1]["properties"]["triggeringLogic"]["conditions"][0]["conditionProperties"]["itemConditions"][0]["conditionProperties"]["propertyValues"] = ["AlarmId"]


def m_samples_default_on(t):
    t["parameters"]["DeploySampleAutomationRules"]["defaultValue"] = True


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


AB = "equals(parameters('IncidentMode'), 'AlertBacked')"


def m_rules_enabled_always(t):
    for r in all_rules(t):
        r["properties"]["enabled"] = True


def m_rules_disabled_always(t):
    for r in all_rules(t):
        r["properties"]["enabled"] = False


def m_credential_ignores_switch(t):
    for r in all_rules(t):
        if "Credential" in r["properties"]["query"].split("| where AlarmCategory == ")[1][:14]:
            r["properties"]["enabled"] = "[%s]" % AB


def m_credential_ignores_mode(t):
    for r in all_rules(t):
        if "Credential" in r["properties"]["query"].split("| where AlarmCategory == ")[1][:14]:
            r["properties"]["enabled"] = "[parameters('EnableCredentialRule')]"


def m_labeler_always_on(t):
    _, auto = rule(t)
    auto["properties"]["triggeringLogic"]["isEnabled"] = True


def m_labeler_never_on(t):
    _, auto = rule(t)
    auto["properties"]["triggeringLogic"]["isEnabled"] = False


def m_rules_only_deployed_in_alert_backed(t):
    nested = next(r for r in t["resources"] if r.get("name") == "deploy-alert-backed-rule")
    nested["condition"] = "[%s]" % AB


def m_rules_deploy_into_external_workspace(t):
    nested = next(r for r in t["resources"] if r.get("name") == "deploy-alert-backed-rule")
    nested["condition"] = "[variables('alarmsTableEnabled')]"


def m_sample_ignores_mode(t):
    for a in samples(t):
        a["condition"] = "[parameters('DeploySampleAutomationRules')]"


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
    r["properties"]["query"] = q.replace('extract(@"Phishing Domain:\\s*([^\\s,;]+\\.[^\\s,;]+)", 1, AlarmText)', '""')


def m_content_domain_from_payload(t):
    r, _ = rule(t)
    r["properties"]["query"] = r["properties"]["query"].replace("pack('Suspicious Domain', SuspiciousDomain,", "pack('Suspicious Domain', AlarmPayload['phishing_domain'],")


def m_domain_regex_greedy(t):
    r, _ = rule(t)
    r["properties"]["query"] = r["properties"]["query"].replace('Phishing Domain:\\s*([^\\s,;]+\\.[^\\s,;]+)', 'Phishing Domain:\\s*(\\S+)')


MUTATIONS = [
    ("severity column not projected", (ROOT, IMPORT), q_replace("SentinelSeverity, AlarmCategory", "AlarmCategory")),
    ("time column not projected", (ROOT, IMPORT), q_replace("| project TimeGenerated, AlarmId", "| project AlarmId")),
    ("company id not projected", (ROOT, IMPORT), q_replace("AlarmId, CompanyId, Title", "AlarmId, Title")),
    ("alarm date not projected", (ROOT, IMPORT), q_replace("Status, AlarmDate, AlarmUrl", "Status, AlarmUrl")),
    ("alarm text not projected", (ROOT, IMPORT), q_replace("Title, AlarmText, AlarmDescription", "Title, AlarmDescription")),
    ("phishing domain fallback lost", (ROOT, IMPORT), q_replace("coalesce(extract(@\"Phishing Domain:", "strcat(extract(@\"Phishing Domain:")),
    ("CVE priority swapped", (ROOT, IMPORT), q_replace("CveId = coalesce(tostring(AlarmPayload['cve_id']),", "CveId = strcat(tostring(AlarmPayload['cve_id']),")),
    ("CVE in the alarm text not read", (ROOT, IMPORT), q_replace("extract(@\"(CVE-[0-9]{4}-[0-9]{4,})\", 1, AlarmText)", "''")),
    ("affected domain keeps its case", (ROOT, IMPORT), q_replace("AffectedDomain = tolower(", "AffectedDomain = (")),
    ("device country keeps the blank placeholder", (ROOT, IMPORT), q_replace("DeviceCountry = trim(@\"[\\s\\-]+\", ", "DeviceCountry = (")),
    ("credential origin default renamed", (ROOT, IMPORT), q_replace('"Historical", "Other")', '"Historical", "Zother")')),
    ("sample automation rules always deploy", (ROOT, IMPORT), m_sample_unconditional),
    ("custom-detail sample adds the SOCRadar label", (ROOT, IMPORT), m_sample_adds_socradar_label),
    ("phishing sample lowers severity", (ROOT, IMPORT), m_sample_phishing_severity),
    ("phishing sample matches the catch-all too", (ROOT, IMPORT), m_sample_phishing_any_rule),
    ("custom-detail sample keys on another detail", (ROOT, IMPORT), m_sample_key_changed),
    ("samples default to on", (ROOT, IMPORT), m_samples_default_on),
    ("phishing domain regex accepts a word with no dot", (ROOT, IMPORT), m_domain_regex_no_dot),
    ("CVE regex wants 9 digits", (ROOT, IMPORT), q_replace("CVE-[0-9]{4}-[0-9]{4,}", "CVE-[0-9]{4}-[0-9]{9,}")),
    ("scanned asset reads only the ip key", (ROOT, IMPORT), q_replace("(?:ip|host)", "(?:ip)")),
    ("IPv4 regex takes three octets", (ROOT, IMPORT), q_replace("(?:\\.[0-9]{1,3}){3}", "(?:\\.[0-9]{1,3}){2}")),
    ("CVSS regex drops decimals", (ROOT, IMPORT), q_replace('"value":([0-9.]+)', '"value":([0-9]+)')),
    ("blank trim keeps the hyphen placeholder", (ROOT, IMPORT), q_replace('@"[\\s\\-]+"', '@"[\\s]+"')),
    ("machine info needs both machine and IP", (ROOT, IMPORT), q_replace("isnotempty(MachineName) or isnotempty(DeviceIp)", "isnotempty(MachineName) and isnotempty(DeviceIp)")),
    ("trailing dot is not trimmed from the domain", (ROOT, IMPORT), q_replace('trim_end(@"[.,;]+", ', "(")),
    ("matched assets dumped as JSON", (ROOT, IMPORT), q_replace('iff(gettype(AlarmPayload[\'matched_asset\']) == "array", strcat_array(AlarmPayload[\'matched_asset\'], ", "), tostring(AlarmPayload[\'matched_asset\']))', "tostring(AlarmPayload['matched_asset'])")),
    ("PII channel renamed", (ROOT, IMPORT), q_replace('"PII Exposure", "PII"', '"PII Exposure", "Other"')),
    ("leak link prefers the repository link", (ROOT, IMPORT), q_replace("coalesce(tostring(AlarmPayload['content_link']), tostring(AlarmPayload['source_link']), tostring(AlarmPayload['repository_url']))", "coalesce(tostring(AlarmPayload['repository_url']), tostring(AlarmPayload['content_link']), tostring(AlarmPayload['source_link']))")),
    ("affected domain wants a 9 letter TLD", (ROOT, IMPORT), q_replace("[A-Za-z]{2,})", "[A-Za-z]{9,})")),
    ("free text cap is 1200", (ROOT, IMPORT), q_replace(", 0, 120)", ", 0, 1200)")),
    ("title label column not projected", (ROOT, IMPORT), q_replace("SuspiciousDomain, SuspiciousDomainLabel,", "SuspiciousDomain,")),
    ("IoC IP column not projected", (ROOT, IMPORT), q_replace("| project TimeGenerated, AlarmId, CompanyId, Title, AlarmText, AlarmDescription,", "| project TimeGenerated, AlarmId, CompanyId, Title, AlarmText,")),
    ("description column not projected", (ROOT, IMPORT), q_replace("AlarmText, AlarmDescription, AlarmMainType", "AlarmText, AlarmMainType")),
    ("classifier drifts in one rule", (ROOT, IMPORT), m_classifier_drifts_in_one_rule),
    ("a pair is dropped from every typed list", (ROOT, IMPORT), m_pair_dropped_everywhere),
    ("catch-all gets a new rule id", (ROOT, IMPORT), m_catch_all_new_guid),
    ("automation rule omits one rule id", (ROOT, IMPORT), m_automation_omits_one_rule),
    ("credential switch is ignored", (ROOT, IMPORT), m_credential_switch_ignored),
    ("DCR drops a payload key a rule reads", (ROOT,), m_dcr_drops_a_key),
    ("title placeholder is the entity column", (ROOT, IMPORT), m_title_uses_entity_column),
    ("credential rule copies the exposed credential", (ROOT, IMPORT), m_credential_copies_secret),
    ("credential origin keys on the word Machine", (ROOT, IMPORT), m_origin_by_machine_word),
    ("leak entity may be a SOCRadar link", (ROOT, IMPORT), m_leak_url_any),
    ("query exceeds the platform limit", (ROOT, IMPORT), m_query_too_long),
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
    ("rule deployment condition dropped", (ROOT, IMPORT), m_rule_deployment_unconditional),
    ("rules stay enabled in Direct mode", (ROOT, IMPORT), m_rules_enabled_always),
    ("rules are never enabled", (ROOT, IMPORT), m_rules_disabled_always),
    ("credential rule ignores its switch", (ROOT, IMPORT), m_credential_ignores_switch),
    ("credential rule ignores the mode", (ROOT, IMPORT), m_credential_ignores_mode),
    ("labeling automation rule always on", (ROOT, IMPORT), m_labeler_always_on),
    ("labeling automation rule never on", (ROOT, IMPORT), m_labeler_never_on),
    ("rules deployed only in AlertBacked (switch back leaves them on)", (ROOT, IMPORT), m_rules_only_deployed_in_alert_backed),
    ("rules deployed into an external workspace", (ROOT, IMPORT), m_rules_deploy_into_external_workspace),
    ("sample automation rules ignore the mode", (ROOT, IMPORT), m_sample_ignores_mode),
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
    import inspect
    blind = []
    total = 0
    for name, paths, mutate in MUTATIONS:
        scoped = "rule(t)" in inspect.getsource(mutate)
        bit = 0
        for index in (range(len(CATS)) if scoped else [0]):
            TARGET[0] = index
            label = "%s [%s]" % (name, CATS[index]) if scoped else name
            originals = {p: open(p, encoding="utf-8").read() for p in paths}
            try:
                changed = False
                for p in paths:
                    template = json.loads(originals[p])
                    before = json.dumps(template, sort_keys=True)
                    mutate(template)
                    changed = changed or json.dumps(template, sort_keys=True) != before
                    with open(p, "w", encoding="utf-8") as handle:
                        handle.write(json.dumps(template, indent=4, ensure_ascii=False))
                if not changed:
                    continue  # the mutation has nothing to bite on in this rule
                total += 1
                bit += 1
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
                print("BLIND  %-52s test still passed" % label)
                blind.append(label)
            else:
                print("caught %-52s" % label)
        if bit == 0:
            print("STALE  %-52s the mutation changes nothing: its target text is gone" % name)
            blind.append(name + " (stale)")
    print("\nblind: %d of %d" % (len(blind), total))
    return 1 if blind else 0


if __name__ == "__main__":
    sys.exit(main())
