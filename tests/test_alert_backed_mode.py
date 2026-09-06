#!/usr/bin/env python3
"""Alert-backed incident mode: the import writes rows, a scheduled rule raises the incidents.

Microsoft Defender's unified queue only shows incidents that are backed by an alert, so
`IncidentMode=AlertBacked` moves incident creation from the import Logic App to a scheduled
analytics rule over SOCRadar_Alarms_CL. Every limit that shapes the design is a platform
number, not a preference, and each one is pinned here:

  - a rule run drops every customised title and severity above 50 distinct values, and
    generates at most 150 alerts, the 150th being a summary  -> the import caps new rows per
    run and the rule query takes at most 149 rows
  - an event ingested after the rule's window has passed is never alerted -> the query filters
    on ingestion_time(), not TimeGenerated (Microsoft's own ingestion-delay guidance)
  - Sync has to find the alarm id when the title override was dropped -> the id is on the URL
    entity, the rule groups by it, and Sync reads it as a third fallback

Run:  python3 tests/test_alert_backed_mode.py
"""
import json
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT = os.path.join(REPO, "azuredeploy.json")
IMPORT = os.path.join(REPO, "Playbooks", "SOCRadar-Alarm-Import", "azuredeploy.json")
SYNC = os.path.join(REPO, "Playbooks", "SOCRadar-Alarm-Sync", "azuredeploy.json")

LOOP = "For_Each_Alarm_AlertBacked"
failures = []
checks = 0


def check(condition, message):
    global checks
    checks += 1
    if not condition:
        failures.append(message)


def rel(path):
    return os.path.relpath(path, REPO)


def load(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def walk(actions, prefix=""):
    found = {}
    for name, body in actions.items():
        found[prefix + name] = body
        if "actions" in body:
            found.update(walk(body["actions"], prefix + name + "/"))
        branch = body.get("else")
        if isinstance(branch, dict) and "actions" in branch:
            found.update(walk(branch["actions"], prefix + name + "/else/"))
    return found


def workflow(template, kind):
    for resource in template["resources"]:
        if resource["type"] != "Microsoft.Logic/workflows":
            continue
        actions = resource["properties"]["definition"]["actions"]
        if kind == "import" and "Pagination_Loop" in actions:
            return resource
        if kind == "sync" and "For_Each_Incident" in actions:
            return resource
    return None


def by_name(actions, name):
    for path, body in actions.items():
        if path.split("/")[-1] == name:
            return path, body
    return None, None


def strings(node):
    if isinstance(node, dict):
        for value in node.values():
            yield from strings(value)
    elif isinstance(node, list):
        for value in node:
            yield from strings(value)
    elif isinstance(node, str):
        yield node


def nested_rule(template):
    for resource in template["resources"]:
        if resource.get("name") == "deploy-alert-backed-rule":
            return resource
    return None


# --------------------------------------------------------------------------- ARM level

root = load(ROOT)
import_pb = load(IMPORT)
sync_pb = load(SYNC)

for path, template in ((ROOT, root), (IMPORT, import_pb)):
    label = rel(path)
    param = template["parameters"].get("IncidentMode")
    check(param is not None, f"{label}: no IncidentMode parameter")
    if param:
        check(param.get("defaultValue") == "Direct", f"{label}: IncidentMode must default to Direct")
        check(param.get("allowedValues") == ["Direct", "AlertBacked"],
              f"{label}: IncidentMode allowedValues must be exactly Direct, AlertBacked")
    gate = template.get("variables", {}).get("alarmsTableEnabled", "")
    check("parameters('EnableAlarmsTable')" in gate and "'AlertBacked'" in gate,
          f"{label}: alarmsTableEnabled must fold EnableAlarmsTable and IncidentMode=AlertBacked")
    # No ARM-scope use of the raw switch survives outside the variable that wraps it; the
    # workflow-scope @parameters() reads stay, they receive the folded value.
    leaks = [s for s in strings({"r": template["resources"], "o": template.get("outputs", {})})
             if s.startswith("[") and "parameters('EnableAlarmsTable')" in s]
    check(not leaks, f"{label}: ARM-scope parameters('EnableAlarmsTable') still used: {leaks[:2]}")

    nested = nested_rule(template)
    check(nested is not None, f"{label}: no deploy-alert-backed-rule nested deployment")
    if nested:
        check(nested.get("condition") == "[equals(parameters('IncidentMode'), 'AlertBacked')]",
              f"{label}: the rule deployment must be conditional on AlertBacked")
        check(nested.get("resourceGroup") == "[parameters('WorkspaceResourceGroup')]",
              f"{label}: the rule deployment must target WorkspaceResourceGroup")
        check(nested["properties"].get("expressionEvaluationOptions", {}).get("scope") == "outer",
              f"{label}: the rule deployment must evaluate expressions in the outer scope")
        wf_name = workflow(template, "import")["name"]
        check(any(wf_name[1:-1] in d for d in nested.get("dependsOn", [])),
              f"{label}: the rule deployment must depend on the import Logic App")

    # The workflow receives the mode and the cap; the cap is derived from the polling interval.
    wf = workflow(template, "import")
    wired = wf["properties"]["parameters"]
    check(wired.get("IncidentMode", {}).get("value") == "[parameters('IncidentMode')]",
          f"{label}: IncidentMode is not wired into the import workflow")
    cap = wired.get("AlertBackedMaxNewPerRun", {}).get("value", "")
    check(cap == "[div(48, add(div(10, parameters('PollingIntervalMinutes')), 1))]",
          f"{label}: AlertBackedMaxNewPerRun formula changed: {cap}")

# Root alone deploys the alarms table: the rule PUT validates the query against the workspace
# schema, so the nested deployment must wait for the table, its DCR and the onboarding state.
root_nested = nested_rule(root)
if root_nested:
    depends = " ".join(root_nested.get("dependsOn", []))
    for needle in ("AlarmsTableName", "AlarmsDcrName", "onboardingStates"):
        check(needle in depends, f"azuredeploy.json: rule deployment does not depend on {needle}")
    check(json.dumps(root_nested["properties"]["template"], sort_keys=True)
          == json.dumps(nested_rule(import_pb)["properties"]["template"], sort_keys=True),
          "the nested rule template differs between azuredeploy.json and the standalone import playbook")

# The cap keeps every rule window under the 50-value cliff: a 10-minute ingestion window sees
# floor(10 / polling) + 1 import runs (each run takes minutes, so one more than the pure ratio).
for polling in (1, 2, 5, 10, 30, 60):
    runs_in_window = 10 // polling + 1
    cap = 48 // runs_in_window
    check(cap >= 1 and runs_in_window * cap <= 50,
          f"cap formula lets a rule run see more than 50 distinct alarms at PollingIntervalMinutes={polling}")
check(48 // (10 // 5 + 1) == 16, "cap at the default 5-minute polling should be 16")

# --------------------------------------------------------------------------- rule resource

if root_nested:
    inner = root_nested["properties"]["template"]["resources"]
    rules = [r for r in inner if r["type"].endswith("/alertRules")]
    autos = [r for r in inner if r["type"].endswith("/automationRules")]
    check(len(rules) == 1 and len(autos) == 1, "nested template must hold exactly one rule and one automation rule")
    if rules:
        rule = rules[0]
        props = rule["properties"]
        query = props["query"]
        check(rule.get("kind") == "Scheduled", "rule kind must be Scheduled")
        check(props.get("enabled") is True, "rule must be enabled")
        check(props.get("queryFrequency") == "PT5M", "rule must run every 5 minutes (platform minimum)")
        check(props.get("queryPeriod") == "PT30M",
              "rule period must be PT30M: TimeGenerated is the ingest call time and a new table's "
              "first ingestion can lag 15 minutes (EXP-AZURE-0177)")
        check("ingestion_time() > ago(10m)" in query,
              "rule query must window on ingestion_time(), not TimeGenerated (ingestion-delay guidance)")
        check(not re.search(r"TimeGenerated\s*[<>]=?\s*ago\(", query),
              "rule query must not filter TimeGenerated with ago(): the engine injects that window")
        check('toupper(Status) == "OPEN"' in query,
              "rule query must only alert on OPEN alarms; a closed SOCRadar alarm must not become an open incident")
        check("summarize arg_max(TimeGenerated, *) by AlarmId" in query,
              "rule query must collapse duplicate rows of one alarm")
        check(query.rstrip().endswith("| take 149"),
              "rule query must cap at 149 rows: the 150th alert of a run is a summary of all of them")
        check("| order by TimeGenerated asc" in query, "rule query must order before take, oldest first")
        check(props.get("eventGroupingSettings", {}).get("aggregationKind") == "AlertPerResult",
              "rule must raise one alert per row")
        check(props.get("triggerOperator") == "GreaterThan" and props.get("triggerThreshold") == 0,
              "rule must fire on any row")
        check(props.get("suppressionEnabled") is False and props.get("suppressionDuration"),
              "rule must declare suppression off with a duration (ARM requires both)")

        override = props.get("alertDetailsOverride", {})
        check("#{{AlarmId}}" in override.get("alertDisplayNameFormat", ""),
              "alert title must carry #<alarm id>: it is Sync's second reader")
        for field in ("alertDisplayNameFormat", "alertDescriptionFormat"):
            placeholders = re.findall(r"\{\{(\w+)\}\}", override.get(field, ""))
            check(len(placeholders) <= 3, f"{field} may use at most 3 placeholders (platform limit)")
        check(override.get("alertSeverityColumnName") == "SentinelSeverity",
              "alert severity must come from the SentinelSeverity column")
        for level, mapped in (("CRITICAL", "High"), ("HIGH", "High"), ("MEDIUM", "Medium")):
            check(f'"{level}"' in query and f'"{mapped}"' in query,
                  f"severity mapping {level}->{mapped} missing from the rule query")
        check('"Medium", "Low")' in query and "Informational" not in query,
              "everything below MEDIUM, INFO included, must become Low: the same mapping Direct mode uses "
              "and the only one Sync's severity rank table knows")

        details = props.get("customDetails", {})
        check(0 < len(details) <= 20, "custom details must be 1..20 keys (platform limit)")
        check(details.get("AlarmId") == "AlarmId", "AlarmId must be a custom detail")

        mappings = props.get("entityMappings", [])
        url = [m for m in mappings if m.get("entityType") == "URL"]
        check(len(url) == 1 and url[0]["fieldMappings"] == [{"identifier": "Url", "columnName": "AlarmUrl"}],
              "the alarm URL must be mapped as the URL entity: it is the identity that survives the 50-value cliff")
        check('strcat("https://platform.socradar.com/company/", CompanyId, "/alarm/", AlarmId)' in query,
              "AlarmUrl must be built as .../company/<id>/alarm/<alarm id>, the shape Sync parses")

        grouping = props.get("incidentConfiguration", {}).get("groupingConfiguration", {})
        check(props.get("incidentConfiguration", {}).get("createIncident") is True, "rule must create incidents")
        check(grouping.get("enabled") is True and grouping.get("matchingMethod") == "Selected"
              and grouping.get("groupByEntities") == ["URL"],
              "alerts must group into one incident by the URL entity (duplicate alerts of one alarm)")
        check(grouping.get("lookbackDuration") == "P7D", "grouping lookback must be the 7-day platform maximum")
        check(grouping.get("reopenClosedIncident") is False, "a duplicate alert must never reopen a closed incident")

        # Every projected column exists in the alarms stream or is derived in the query.
        projected = re.search(r"\| project ([^\n]+)", query).group(1)
        columns = {c.strip() for c in projected.split(",")}
        dcr = [r for r in root["resources"] if r["type"] == "Microsoft.Insights/dataCollectionRules"
               and "AlarmsDcrName" in r["name"]][0]
        declared = set()
        for stream in dcr["properties"]["streamDeclarations"].values():
            declared |= {c["name"] for c in stream["columns"]}
        derived = {"AlarmUrl", "SentinelSeverity"}
        missing = columns - declared - derived
        check(not missing, f"rule query projects columns the alarms table does not have: {sorted(missing)}")
        check(set(details.values()) <= columns, "every custom detail must be a projected column")

        # ARM would read a string that starts with [ and ends with ] as an expression, and the
        # Content Hub packaging tool escapes such strings (EXP-AZURE-0161). None may exist here.
        bracketed = [s for s in strings(rule) if s.startswith("[") and s.endswith("]") and not s.startswith("[concat")
                     and not s.startswith("[resourceId") and not s.startswith("[guid")]
        check(not bracketed, f"rule carries literal strings that ARM would parse as expressions: {bracketed[:2]}")

    if autos:
        auto = autos[0]["properties"]
        check(auto.get("order") == 1, "automation rule must declare order")
        logic = auto.get("triggeringLogic", {})
        check(logic.get("triggersOn") == "Incidents" and logic.get("triggersWhen") == "Created",
              "automation rule must trigger on incident creation")
        conditions = logic.get("conditions", [])
        check(len(conditions) == 1 and conditions[0]["conditionProperties"]["propertyName"] == "IncidentRelatedAnalyticRuleIds"
              and conditions[0]["conditionProperties"]["operator"] == "Contains"
              and "alertBackedRuleId" in conditions[0]["conditionProperties"]["propertyValues"][0],
              "automation rule must match incidents of this rule by IncidentRelatedAnalyticRuleIds Contains <rule id>")
        actions = auto.get("actions", [])
        check(len(actions) == 1 and actions[0]["actionType"] == "ModifyProperties"
              and actions[0]["actionConfiguration"].get("labels") == [{"labelName": "SOCRadar"}],
              "automation rule must add exactly the SOCRadar label: it is what Sync filters on")
        check(any("alertBackedRuleId" in d for d in autos[0].get("dependsOn", [])),
              "automation rule must depend on the analytics rule")

# --------------------------------------------------------------------------- import workflow

for path, template in ((ROOT, root), (IMPORT, import_pb)):
    label = rel(path)
    wf = workflow(template, "import")
    definition = wf["properties"]["definition"]
    actions = walk(definition["actions"])

    check(definition["parameters"].get("IncidentMode", {}).get("defaultValue") == "Direct",
          f"{label}: workflow IncidentMode must default to Direct")
    check(definition["parameters"].get("AlertBackedMaxNewPerRun", {}).get("type") == "Int",
          f"{label}: AlertBackedMaxNewPerRun must be an Int workflow parameter")

    # Direct loop: gated on the mode, body untouched.
    _, should = by_name(actions, "Check_If_Should_Import")
    expr = json.dumps(should["expression"])
    check('{"equals": ["@parameters(\'IncidentMode\')", "Direct"]}' in expr and expr.startswith('{"and"'),
          f"{label}: Check_If_Should_Import must require IncidentMode=Direct")
    create_path, _ = by_name(actions, "Create_New_Incident")
    check(create_path and "Check_If_Should_Import" in create_path and LOOP not in create_path,
          f"{label}: Create_New_Incident must stay under the Direct-mode gate")

    # AlertBacked loop: sequential sibling inside the page loop.
    loop_path, loop = by_name(actions, LOOP)
    check(loop_path == f"Pagination_Loop/{LOOP}", f"{label}: {LOOP} must sit directly in Pagination_Loop")
    if loop:
        check(loop.get("runtimeConfiguration", {}).get("concurrency", {}).get("repetitions") == 1,
              f"{label}: {LOOP} must run sequentially, the cap counter is a plain variable")
        check(loop.get("foreach") == actions["Pagination_Loop/For_Each_Alarm"].get("foreach"),
              f"{label}: {LOOP} must iterate the same page array as For_Each_Alarm")
        after = loop.get("runAfter", {}).get("For_Each_Alarm", [])
        check("Failed" in after and "Succeeded" in after,
              f"{label}: {LOOP} must run after For_Each_Alarm even when a Direct record failed")
        inc = actions["Pagination_Loop/Increment_Page"].get("runAfter", {})
        check(set(inc.keys()) == {LOOP} and "Failed" in inc[LOOP],
              f"{label}: Increment_Page must wait for {LOOP} and still advance past a failed record")

        _, gate = by_name(actions, "Check_AlertBacked_Should_Import")
        gate_expr = json.dumps(gate["expression"]) if gate else ""
        for needle in ('"@parameters(\'IncidentMode\')", "AlertBacked"', '"@variables(\'capped\')", false',
                       '"@variables(\'marker_read_failed\')", false', "@parameters('ImportAllStatuses')"):
            check(needle in gate_expr, f"{label}: Check_AlertBacked_Should_Import lacks {needle}")

        _, read = by_name(actions, "Read_Seen_Marker")
        check(read and read["inputs"]["method"] == "GET" and "RowKey='alarm-" in read["inputs"]["uri"]
              and "CheckpointTableUrl" in read["inputs"]["uri"],
              f"{label}: Read_Seen_Marker must GET the alarm-<id> row of the checkpoint table")
        _, marker_read = by_name(actions, "Check_Marker_Read")
        check(marker_read and "Failed" in marker_read["runAfter"].get("Read_Seen_Marker", []),
              f"{label}: Check_Marker_Read must run after a failed (404) marker read")
        check(marker_read and "404" in json.dumps(marker_read["expression"]) and "200" in json.dumps(marker_read["expression"]),
              f"{label}: Check_Marker_Read must accept exactly 200 and 404")
        flag_path, flag = by_name(actions, "Flag_Marker_Read_Failed")
        check(flag_path and "/else/" in flag_path and flag["inputs"] == {"name": "marker_read_failed", "value": True},
              f"{label}: any other marker status must raise marker_read_failed")
        _, is_new = by_name(actions, "Check_Alarm_Is_New")
        check(is_new and "404" in json.dumps(is_new["expression"]), f"{label}: Check_Alarm_Is_New must test for 404")

        _, ingest = by_name(actions, "Ingest_Alarm_Row")
        _, direct_ingest = by_name(actions, "Ingest_To_Custom_Table")
        check(ingest and ingest["inputs"]["method"] == "POST"
              and list(ingest["inputs"]["body"][0].keys()) == list(direct_ingest["inputs"]["body"][0].keys()),
              f"{label}: Ingest_Alarm_Row must write the same columns as the Direct-mode ingest")
        check(ingest and f"items('{LOOP}')" in json.dumps(ingest["inputs"]) and "items('For_Each_Alarm')" not in json.dumps(ingest["inputs"]),
              f"{label}: Ingest_Alarm_Row must read its own loop item")
        _, write = by_name(actions, "Write_Seen_Marker")
        check(write and write["inputs"]["method"] == "PUT" and write["runAfter"] == {"Ingest_Alarm_Row": ["Succeeded"]}
              and write["inputs"]["body"]["RowKey"].startswith("alarm-"),
              f"{label}: Write_Seen_Marker must PUT alarm-<id> only after the row was ingested")
        check(write and write["inputs"]["headers"].get("Content-Type") == "application/json;odata=noop",
              f"{label}: Write_Seen_Marker needs the odata=noop Content-Type (Table Storage 415 otherwise)")
        _, incr = by_name(actions, "Increment_New_Alarms")
        check(incr and incr["runAfter"] == {"Write_Seen_Marker": ["Succeeded"]},
              f"{label}: the counter must move only after the marker is written")
        _, cap = by_name(actions, "Check_Cap_Reached")
        check(cap and "@parameters('AlertBackedMaxNewPerRun')" in json.dumps(cap["expression"])
              and "greaterOrEquals" in json.dumps(cap["expression"]),
              f"{label}: Check_Cap_Reached must compare the counter to AlertBackedMaxNewPerRun")
        _, set_capped = by_name(actions, "Set_Capped")
        check(set_capped and set_capped["inputs"] == {"name": "capped", "value": True},
              f"{label}: hitting the cap must set capped")
        for forbidden in ("Create_New_Incident", "Create_Closed_Incident", "Add_Bookmark", "Create_Bookmark"):
            check(not any(p.startswith(loop_path + "/") and p.endswith("/" + forbidden) for p in actions),
                  f"{label}: {forbidden} must not exist inside {LOOP}")
        _, audit = by_name(actions, "Log_Alarm_Ingested_Event")
        check(audit and audit["inputs"]["body"][0]["EventType"] == "AlarmIngested",
              f"{label}: the alert-backed ingest must leave an AlarmIngested audit row")

    # Run-scoped variables and the checkpoint hold.
    for var_action in ("Initialize_New_Alarms", "Initialize_Capped", "Initialize_Marker_Read_Failed"):
        check(var_action in definition["actions"], f"{label}: missing {var_action}")
    check(definition["actions"]["Pagination_Loop"].get("runAfter") == {"Initialize_Marker_Read_Failed": ["Succeeded"]},
          f"{label}: Pagination_Loop must wait for the new variables")
    _, verify = by_name(actions, "Verify_Import_Complete")
    check("marker_read_failed" in json.dumps(verify["expression"]),
          f"{label}: a failed marker read must make the import incomplete (checkpoint held)")
    _, ckpt = by_name(actions, "Write_Checkpoint")
    last = ckpt["inputs"]["body"].get("LastRunUtc", "")
    check("variables('capped')" in last and "body('Read_Checkpoint')?['LastRunUtc']" in last
          and "outputs('Capture_Run_Start')" in last,
          f"{label}: a capped run must rewrite the previous LastRunUtc instead of advancing")
    check(ckpt["inputs"]["body"].get("Capped") == "@{variables('capped')}"
          and ckpt["inputs"]["body"].get("NewAlarmsIngested") == "@{variables('new_alarms')}",
          f"{label}: the checkpoint row must record the cap state")

# The two copies of the import definition are byte-identical.
check(json.dumps(workflow(root, "import")["properties"]["definition"], sort_keys=True)
      == json.dumps(workflow(import_pb, "import")["properties"]["definition"], sort_keys=True),
      "import workflow definition differs between azuredeploy.json and Playbooks/SOCRadar-Alarm-Import")

# --------------------------------------------------------------------------- sync workflow

for path, template in ((ROOT, root), (SYNC, sync_pb)):
    label = rel(path)
    actions = walk(workflow(template, "sync")["properties"]["definition"]["actions"])
    _, lookup = by_name(actions, "Check_Needs_Entity_Lookup")
    check(lookup is not None, f"{label}: no Check_Needs_Entity_Lookup")
    if lookup:
        expr = json.dumps(lookup["expression"])
        check('"@outputs(\'Extract_Alarm_ID\')", ""' in expr and '"Closed"' in expr
              and '"@outputs(\'Check_Has_Synced_Tag\')", false' in expr,
              f"{label}: the entity lookup must run only for closed, unsynced incidents without a label/title id")
        check(lookup["runAfter"] == {"Check_Has_Synced_Tag": ["Succeeded"]},
              f"{label}: Check_Needs_Entity_Lookup must follow Check_Has_Synced_Tag")
    _, get = by_name(actions, "Get_Incident_Entities")
    check(get and get["inputs"]["method"] == "POST" and "/entities?api-version=" in get["inputs"]["uri"]
          and get["inputs"]["authentication"] == {"type": "ManagedServiceIdentity"},
          f"{label}: Get_Incident_Entities must POST incidents/<id>/entities with the managed identity")
    _, flt = by_name(actions, "Filter_Alarm_Url_Entities")
    check(flt and "'Url'" in flt["inputs"]["where"] and "'/alarm/'" in flt["inputs"]["where"],
          f"{label}: only URL entities that point at a SOCRadar alarm may be read")
    _, from_entities = by_name(actions, "Alarm_ID_From_Entities")
    check(from_entities and "'/alarm/'" in from_entities["inputs"] and "'?'" in from_entities["inputs"],
          f"{label}: Alarm_ID_From_Entities must take the id after /alarm/ and strip a query string")
    _, resolve = by_name(actions, "Resolve_Alarm_ID")
    check(resolve and "actions('Alarm_ID_From_Entities')?['outputs']" in resolve["inputs"]
          and "outputs('Extract_Alarm_ID')" in resolve["inputs"],
          f"{label}: Resolve_Alarm_ID must fall back to the entity id through actions(), the lookup may be skipped")
    check(resolve and resolve["runAfter"] == {"Check_Needs_Entity_Lookup": ["Succeeded"]},
          f"{label}: Resolve_Alarm_ID must follow the lookup")
    _, closed = by_name(actions, "Check_If_Closed_And_Not_Synced")
    check(closed["runAfter"] == {"Resolve_Alarm_ID": ["Succeeded"]},
          f"{label}: Check_If_Closed_And_Not_Synced must wait for Resolve_Alarm_ID")
    # Every downstream reader uses the resolved id; only the resolver and its gate read Extract.
    stale = [p for p, body in actions.items() if "outputs('Extract_Alarm_ID')" in json.dumps(body)
             and p.split("/")[-1] not in ("Check_Needs_Entity_Lookup", "Resolve_Alarm_ID", "For_Each_Incident")
             and not p.endswith("Check_Needs_Entity_Lookup") and "Check_Needs_Entity_Lookup/" not in p]
    # Container actions (If/Foreach) embed their children, so drop paths that are ancestors of the gate.
    stale = [p for p in stale if not (actions[p].get("type") in ("If", "Foreach") and any(
        q.startswith(p + "/") for q in actions if q.endswith("Check_Needs_Entity_Lookup") or q.endswith("Resolve_Alarm_ID")))]
    check(not stale, f"{label}: actions still read the unresolved Extract_Alarm_ID: {stale[:3]}")
    for name in ("Update_SOCRadar_Status", "Update_SOCRadar_Severity"):
        _, body = by_name(actions, name)
        check(body and "outputs('Resolve_Alarm_ID')" in json.dumps(body["inputs"].get("body")),
              f"{label}: {name} must send the resolved alarm id")

check(json.dumps(workflow(root, "sync")["properties"]["definition"], sort_keys=True)
      == json.dumps(workflow(sync_pb, "sync")["properties"]["definition"], sort_keys=True),
      "sync workflow definition differs between azuredeploy.json and Playbooks/SOCRadar-Alarm-Sync")

# --------------------------------------------------------------------------- report

if failures:
    print("ALERT-BACKED MODE CHECK FAILED\n")
    for item in failures:
        print("  - " + item)
    print(f"\n{len(failures)} problem(s) in {checks} checks.")
    sys.exit(1)
print(f"Alert-backed mode: rule limits, import cap and checkpoint hold, Sync entity reader verified in {checks} checks.")
