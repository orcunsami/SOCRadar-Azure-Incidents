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
import hashlib
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


SEVERITY_MARK = "SOCRadar severity: "

CATEGORIES = ["Phishing", "Credential", "DataLeak", "Vulnerability", "Other"]
ENTITIES = {  # entity mappings after AlarmUrl, as (type, identifier, column)
    "Phishing": [("DNS", "DomainName", "SuspiciousDomain"), ("IP", "Address", "SuspiciousIp")],
    "Credential": [("Host", "HostName", "MachineName"), ("IP", "Address", "DeviceIp")],
    "DataLeak": [("URL", "Url", "LeakUrl")],
    "Vulnerability": [("IP", "Address", "AffectedIp"), ("DNS", "DomainName", "AffectedDomain")],
    "Other": [("IP", "Address", "IoCIp1"), ("DNS", "DomainName", "SuspiciousDomain"), ("URL", "Url", "IoCUrl1")],
}
SHARED_DETAILS = {"AlarmId": "AlarmId", "AlarmMainType": "AlarmMainType", "AlarmSubType": "AlarmSubType",
                  "SocradarSeverity": "Severity", "AlarmStatus": "Status"}
TYPED_DETAILS = {
    "Phishing": ["SuspiciousDomain", "SuspiciousIp", "PhishingScore", "PhishingKeyword"],
    "Credential": ["CredentialOrigin", "HasMachineInfo", "MachineName", "DeviceIp", "DeviceCountry", "MalwareFamily", "AssetMatch"],
    "DataLeak": ["LeakChannel", "LeakSource", "LeakUrl", "AttackType", "MatchedAsset"],
    "Vulnerability": ["CveId", "CvssScore", "AffectedSoftware", "AffectedIp", "AffectedDomain"],
    "Other": ["SuspiciousDomain"],
}
CONTENT_FIRST = {"Phishing": "Suspicious Domain", "Credential": "Origin", "DataLeak": "Channel",
                 "Vulnerability": "CVE", "Other": "Suspicious Domain"}
# Change detector for the per-type part of each query (the extend block and the Content pack): the
# behaviour tests above cover what the expressions must do, the pin makes any edit of them deliberate.
# After an intended change, print the new values with `python3 tests/test_alert_backed_mode.py --pins`.
BLOCK_PINS = {
    "Phishing": [
        "f6675c6070a2855f0ed5",
        "e69bab7c7447bb03ce59"
    ],
    "Credential": [
        "2c973c543de2dd2dff7d",
        "9b37c6665bd08d164609"
    ],
    "DataLeak": [
        "62776d49ff712af88e76",
        "362937f5389e97dc798b"
    ],
    "Vulnerability": [
        "36f42463aa35a0b351cd",
        "48425d0e9a53ae6118d9"
    ],
    "Other": [
        "9a8193c5d97555e5aeaa",
        "7a348b91825745a0217f"
    ]
}
RULE_IDS = {"Phishing": "alertBackedPhishingRuleId", "Credential": "alertBackedCredentialRuleId",
            "DataLeak": "alertBackedDataLeakRuleId", "Vulnerability": "alertBackedVulnerabilityRuleId",
            "Other": "alertBackedRuleId"}
# Every (main type, sub type) pair the research set holds, with the one rule that must take it.
FIXTURE = [
    ("Brand Protection", "Impersonating Domain", "Phishing"), ("Phishing Domain", "State Change", "Phishing"),
    ("Vulnerability Monitoring", "Mobile Application Vulnerability", "Vulnerability"),
    ("Vulnerability Monitoring", "Network System Vulnerability", "Vulnerability"),
    ("Vulnerability Intelligence", "Vulnerability Intelligence Subscription", "Vulnerability"),
    ("Deep&Dark Web Monitoring", "Stolen Credentials On Dark Web Bot Market", "Credential"),
    ("Botnet", "Stolen Credentials On Dark Web Bot Market", "Credential"),
    ("Deep&Dark Web Monitoring", "Black Market Botnet Detection", "Credential"),
    ("Surface Web Monitoring", "Code Repository Data Leak", "DataLeak"),
    ("Deep&Dark Web Monitoring", "Dark Web Suspicious Content", "DataLeak"),
    ("Deep&Dark Web Monitoring", "IM Platform Suspicious Content", "DataLeak"),
    ("Deep&Dark Web Monitoring", "PII Exposure", "DataLeak"),
    ("Surface Web Monitoring", "Public Storage Leak", "DataLeak"),
    ("Surface Web Monitoring", "Malware Analysis Service Monitoring", "DataLeak"),
    ("Surface Web Monitoring", "Surface Web Suspicious Content", "Other"),
    ("Threat Hunting", "Proactive Threat Hunting", "Other"),
    ("Brand Protection", "Social Media Risk", "Other"), ("Brand Protection", "Reputation", "Other"),
    ("Configuration Weakness", "Mobile Application Security", "Other"),
    ("Configuration Weakness", "SSL Security", "Other"),
    ("Internet Asset Inventory Monitoring", "Asset Discovery", "Other"),
    ("Internet Asset Inventory Monitoring", "DNS Information Change", "Other"),
    ("Supply Chain Intelligence", "Security Incidents", "Other"),
    ("Deep&Dark Web Monitoring", "A Sub Type SOCRadar Adds Next Year", "Other"),
    ("A New Main Type", "Anything", "Other"),
    # the same sub type exists under two main types and is a credential under both
    ("Some Other Main Type", "Stolen Credentials On Dark Web Bot Market", "Credential"),
]


_context = [""]


def eval_switch(expression, mode, credential=True):
    """Evaluate the small boolean ARM expressions that switch a rule: equals() and and() over two parameters."""
    if not isinstance(expression, str):
        return expression
    text = expression[1:-1] if expression.startswith("[") and expression.endswith("]") else expression
    text = text.replace("parameters('IncidentMode')", repr(mode)).replace("parameters('EnableCredentialRule')", repr(credential))
    text = re.sub(r"\band\(", "all_of(", text)
    text = re.sub(r"\bequals\(", "same(", text)
    if re.search(r"[^\w\s,()'=.-]", text):
        raise ValueError(expression)
    return eval(text, {"__builtins__": {}}, {"all_of": lambda *a: all(a), "same": lambda a, b: a == b})


def check(condition, message):
    global checks
    checks += 1
    if not condition:
        failures.append(f"[{_context[0]}] {message}" if _context[0] else message)


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


def classify(query, main, sub):
    """Evaluate the case() classifier the rule really carries, not a copy of it."""
    body = re.search(r"\| extend AlarmCategory = case\((.*?)\n    \"Other\"\)", query, re.S)
    if body is None:
        return None
    for cond, label in re.findall(r'(.*?),\s*"(Phishing|Vulnerability|Credential|DataLeak)",', body.group(1), re.S):
        expr = re.sub(r'(\w+) =~ "([^"]+)"', lambda m: f'({m.group(1)}.lower() == {m.group(2).lower()!r})', cond)
        expr = re.sub(r'(\w+) in~ \(([^)]*)\)',
                      lambda m: f'({m.group(1)}.lower() in {[x.strip().strip(chr(34)).lower() for x in m.group(2).split(chr(34) + ", " + chr(34))]!r})',
                      expr)
        expr = " ".join(expr.split())
        if eval(expr, {}, {"AlarmMainType": main, "AlarmSubType": sub}):
            return label
    return "Other"


# What the catch-all must label each main type with (the Push repo's tacticsMap for the types that reach it).
TACTICS_EXPECTED = {
    "Attack Surface Management": "Reconnaissance", "Executive Protection": "Reconnaissance",
    "Industry Attacks Monitoring": "Reconnaissance", "Internet Asset Inventory Monitoring": "Reconnaissance",
    "VIP Protection": "Reconnaissance", "Botnet": "CredentialAccess", "Deep&Dark Web Monitoring": "CredentialAccess",
    "Configuration Weakness": "InitialAccess", "Fraud Protection": "InitialAccess", "Supply Chain Intelligence": "InitialAccess",
    "Brand Protection": "ResourceDevelopment,InitialAccess", "Domain": "ResourceDevelopment,InitialAccess",
    "Phishing Domain": "ResourceDevelopment,InitialAccess", "Surface Web Monitoring": "Reconnaissance,Exfiltration",
    "Threat Hunting": "InitialAccess,CommandAndControl", "A New Main Type": "Reconnaissance",
}


def _case_of(query, column, last_default, main):
    """Evaluate a one-column case() over AlarmMainType that the catch-all really carries."""
    body = re.search(r"\| extend %s = case\(\n(.*?)\n    %s\)" % (column, re.escape(last_default)), query, re.S)
    if body is None:
        return None
    for line in body.group(1).split("\n"):
        hit = re.fullmatch(r'\s*(.+), ([\'"])([A-Za-z0-9,\[\]"]+)\2,', line)
        if hit is None:
            return None
        expr = re.sub(r'(\w+) =~ "([^"]+)"', lambda m: f'({m.group(1)}.lower() == {m.group(2).lower()!r})', hit.group(1))
        expr = re.sub(r'(\w+) in~ \(([^)]*)\)',
                      lambda m: f'({m.group(1)}.lower() in {[x.strip().strip(chr(34)).lower() for x in m.group(2).split(chr(34) + ", " + chr(34))]!r})',
                      expr)
        if eval(expr, {}, {"AlarmMainType": main}):
            return hit.group(3)
    return last_default.strip("\"'")


def tactics_of(query, main):
    """Evaluate the AlarmTactics case() the catch-all really carries."""
    return _case_of(query, "AlarmTactics", '"Reconnaissance"', main)


def techniques_of(query, main):
    """Evaluate the AlarmTechniques case() (a JSON array string, returned here as a comma list)."""
    raw = _case_of(query, "AlarmTechniques", "'[\"T1595\",\"T1596\"]'", main)
    if raw is None or not (raw.startswith('["') and raw.endswith('"]')):
        return None  # a comma list left the alert's Techniques empty in the live test: it has to be a JSON array
    return ",".join(json.loads(raw))


# What the catch-all must label each main type's techniques with (the Push repo's tacticsMap).
TECHNIQUES_EXPECTED = {
    "Attack Surface Management": "T1595,T1596", "Executive Protection": "T1589,T1593",
    "Industry Attacks Monitoring": "T1591", "Internet Asset Inventory Monitoring": "T1595", "VIP Protection": "T1589",
    "Botnet": "T1555,T1056", "Deep&Dark Web Monitoring": "T1555,T1110", "Configuration Weakness": "T1190",
    "Fraud Protection": "T1566", "Supply Chain Intelligence": "T1195",
    "Brand Protection": "T1583,T1566", "Domain": "T1583,T1566", "Phishing Domain": "T1583,T1566",
    "Surface Web Monitoring": "T1593,T1567", "Threat Hunting": "T1566,T1071", "A New Main Type": "T1595,T1596",
}


def origin_of(query, title, main="Deep&Dark Web Monitoring"):
    """Evaluate the CredentialOrigin case() of the query (has = word match, =~ = case-insensitive equality)."""
    line = re.search(r"\| extend CredentialOrigin = case\((.*)\)\n", query).group(1)
    words = re.findall(r"[\w&]+", title.lower())
    for cond, label in re.findall(r'(.*?),\s*"(\w+)"(?:,|$)', line):
        expr = re.sub(r'Title has "([^"]+)"',
                      lambda m: "(%r in ' '.join(words))" % " ".join(re.findall(r"[\w&]+", m.group(1).lower())), cond)
        expr = re.sub(r'AlarmMainType =~ "([^"]+)"', lambda m: "(main.lower() == %r)" % m.group(1).lower(), expr)
        if eval(" ".join(expr.split()), {}, {"words": words, "main": main}):
            return label
    return re.search(r',\s*"(\w+)"\s*$', line).group(1)  # the default branch the query really carries


def kql_regex(query, arg):
    """The regex literal of the extract() whose input is `arg`."""
    m = re.search(r'extract\(@"([^"]+)", 1, ' + re.escape(arg), query) or \
        re.search(r"extract\(@'([^']+)', 1, " + re.escape(arg), query)
    return m.group(1) if m else None


def kql_trim(pattern_literal, text):
    """KQL trim(regex, text): strip a match of the regex from both ends."""
    return re.sub(r"(?:%s)$" % pattern_literal, "", re.sub(r"^(?:%s)" % pattern_literal, "", text))


# --------------------------------------------------------------------------- ARM level

root = load(ROOT)
import_pb = load(IMPORT)
sync_pb = load(SYNC)

for path, template in ((ROOT, root), (IMPORT, import_pb)):
    label = rel(path)
    param = template["parameters"].get("IncidentMode")
    check(param is not None, f"{label}: no IncidentMode parameter")
    if param:
        check(param.get("defaultValue") == "AlertBacked", f"{label}: IncidentMode must default to AlertBacked")
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
        # Deployed in Direct mode too, switched off: an incremental deployment never deletes a rule
        # whose condition went false, so switching back to Direct would leave them raising a second
        # incident per alarm. Only where the alarms table exists (same resource group).
        check(nested.get("condition") == "[and(variables('alarmsTableEnabled'), not(variables('isExternalWorkspace')))]",
              f"{label}: the rule deployment must exist whenever the alarms table does and the workspace is in "
              f"this resource group, not only in AlertBacked (found {nested.get('condition')!r})")
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
    samples = [a for a in autos if "Sample" in a["name"]]
    autos = [a for a in autos if "Sample" not in a["name"]]
    check(len(rules) == 5 and len(autos) == 1 and len(samples) == 2,
          "nested template must hold five rules, one labeling automation rule and two optional sample automation rules")
    by_cat = {}
    for found in rules:
        label_match = re.search(r'\| where AlarmCategory == "(\w+)"', found["properties"]["query"])
        check(label_match is not None, "every rule query must filter on exactly one AlarmCategory")
        if label_match:
            by_cat[label_match.group(1)] = found
    check(sorted(by_cat) == sorted(CATEGORIES), f"the five rules must cover exactly {CATEGORIES}: got {sorted(by_cat)}")
    for cat, rule in by_cat.items():
        _context[0] = cat
        props = rule["properties"]
        query = props["query"]
        check(rule.get("kind") == "Scheduled", "rule kind must be Scheduled")
        switch = props.get("enabled")
        try:
            direct_on = eval_switch(switch, "Direct", True)
            ab_on = eval_switch(switch, "AlertBacked", True)
            ab_off_cred = eval_switch(switch, "AlertBacked", False)
        except ValueError:
            check(False, f"rule is switched by an expression this test cannot read: {switch!r}")
        else:
            check(direct_on is False,
                  "rule must be off in Direct mode: switching back from AlertBacked would otherwise raise a second incident per alarm")
            check(ab_on is True, "rule must be on in AlertBacked mode")
            check(ab_off_cred is (cat != "Credential"),
                  "only the credential rule has an off switch (EnableCredentialRule), and it must honour it")
        check(props.get("queryFrequency") == "PT10M",
              "rule must run every 10 minutes: the platform runs a query ~6 min behind the clock, so a shorter "
              "interval hides the previous alert from the next run and every alarm alerts twice (measured)")
        check(props.get("queryPeriod") == "P1D",
              "rule period must be P1D: the SecurityAlert read that drops already-alerted alarms and the "
              "backlog both need the day, and TimeGenerated is the ingest call time (EXP-AZURE-0177)")
        check("ingestion_time() > ago(1d)" in query and "ingestion_time() < ago(12m)" in query,
              "rule query must window on ingestion_time(), not TimeGenerated, and hold rows back 12 minutes "
              "so the previous run's alert is visible before the row is considered again")
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
        # The SOCRadar level rides in the alert description (the incident inherits it): it is the
        # only channel Sync can read without new credentials, and the label is not there.
        check(override.get("alertDescriptionFormat") == "{{AlarmDescription}}",
              "alert description must be the composed AlarmDescription column")
        # The description is a markdown report (SOCRadar Alarm header, details, content table,
        # byte-budgeted link) rather than a flat substring; the two invariants Sync and the
        # 4800-byte budget actually depend on are that AlarmText still feeds it and the
        # severity marker still closes it.
        body_extend = re.search(r"\| extend DescriptionBody = ([^\n]+)", query)
        check("substring(AlarmText, 0, 1500)" in query,
              "AlarmDescription must still derive from substring(AlarmText, 0, 1500)")
        check(body_extend is not None and f'"\\n\\n{SEVERITY_MARK}"' in body_extend.group(1)
              and body_extend.group(1).rstrip().endswith('toupper(Severity))'),
              "DescriptionBody must end with the newline + 'SOCRadar severity: ' + toupper(Severity) marker")
        # The Defender portal shows the description as raw text (measured 2 Nov 2026): a pipe
        # table appears as "| Field | Value |" rows, and a link glued to the severity line
        # reads "HIGHView in SOCRadar". So content is "Field: value" lines and the link is
        # separated by a blank line.
        check("| Field | Value |" not in query and "|---|" not in query,
              "content must be plain 'Field: value' lines, not a pipe table (Defender does not render markdown)")
        check('strcat("\\n\\nView in SOCRadar: ", AlarmUrl)' in query,
              "the SOCRadar link must start after a blank line, not glue onto the severity marker")
        # Defender shows the description as raw text, so markdown escapes would be read literally
        # ("\\_admin\\_", "&lt;", "\\|"). The alert description is plain text on purpose.
        check("&lt;" not in query and "&gt;" not in query and "SafeValue" not in query,
              "description must not HTML-escape: Defender shows the text raw")
        check(not any(f'"{c}", "\\\\{c}"' in query for c in "*_~[]|"),
              "description must not backslash-escape markdown characters: Defender shows them raw")
        check('"`", "\'\'"' not in query, "description must not rewrite backticks: it is not markdown")
        # One alert per alarm. Two overlapping runs see every row and the platform can delay a run
        # (measured: 5 alerts per alarm, and a new incident 85 s after an analyst closed the first),
        # so rows whose AlarmId already has a SecurityAlert are dropped before they can alert again.
        check("join kind=leftanti Alerted on $left.AlarmId == $right.AlertedAlarmId" in query
              and query.index("join kind=leftanti Alerted") < query.index("summarize arg_max(TimeGenerated, *) by AlarmId"),
              "rule must drop alarms that already have an alert before it summarizes")
        check("tostring(parse_json(tostring(parse_json(tostring(ExtendedProperties))['Custom Details'])).AlarmId[0])" in query,
              "the alerted-AlarmId read must use the double-encoded Custom Details shape measured live")
        check("union isfuzzy=true (datatable(ExtendedProperties:string)[]), SecurityAlert" in query,
              "the SecurityAlert read must tolerate a workspace where that table does not exist yet")
        check("extend AlarmDescription = " in query and query.index("| extend DescriptionBody") < query.index("| project "),
              "AlarmDescription must be derived before the projection")
        check("base64_encode_tostring(" in query and "4800" in query and "4900" in query,
              "AlarmDescription must stay inside the 4800/4900-byte alert-description budget")
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
        # AlarmUrl stays first in every rule: it is the one entity every alarm always has, and Sync
        # reads the alarm id from it when a title was rewritten. The platform cap is 5 mappings
        # (live-measured: "Invalid length of '10' for 'EntityMappings' ... between '1' and '5'").
        check(mappings and mappings[0] == {"entityType": "URL", "fieldMappings": [{"identifier": "Url", "columnName": "AlarmUrl"}]},
              "AlarmUrl must still be the first URL entity mapping")
        want_entities = ENTITIES[cat]
        got_entities = [(m["entityType"], m["fieldMappings"][0]["identifier"], m["fieldMappings"][0]["columnName"])
                        for m in mappings[1:]]
        check(all(len(m["fieldMappings"]) == 1 for m in mappings), "every entity mapping must be a single identifier")
        check(len(mappings) <= 5, f"entityMappings above 5 are rejected by the platform (measured): found {len(mappings)}")
        check(got_entities == want_entities, f"entity mappings after AlarmUrl must be {want_entities}, got {got_entities}")
        # The monitored asset (the customer's own brand) is never an entity in any rule, and the regex
        # domain IoCDomain1 only feeds the catch-all: on a lookalike alarm it is a name server.
        mapped_cols = {m["fieldMappings"][0]["columnName"] for m in mappings}
        check("MonitoredAsset" not in mapped_cols, "the monitored asset must not be an entity")
        check("IoCDomain1" not in mapped_cols,
              "the regex-found domain must not be an entity in any rule: on a lookalike alarm it is a name server")
        check(details.get("MonitoredAsset") == "MonitoredAsset" and details.get("AlarmCategory") == "AlarmCategory",
              "MonitoredAsset and AlarmCategory must be custom details in every rule")
        for key in SHARED_DETAILS:
            check(details.get(key) == SHARED_DETAILS[key], f"custom detail {key} must be shared by every rule")
        for key in TYPED_DETAILS[cat]:
            check(details.get(key) == key, f"custom detail {key} must be set on the {cat} rule")
        check(all(len(k) <= 20 for k in details), "custom detail keys must be 20 characters or fewer")
        check('IoCUrl1 = iff(IoCUrl1 has "socradar.com", "", IoCUrl1)' in query,
              "a SOCRadar platform link must not become an IoC URL entity")
        check("array_slice(ContentRows, 0, 5)" in query,
              "the Content block must stop at the first 5 fields, not list every field the alarm carries")
        check(query.count("| extend AlarmContent = pack('") == 1 and f"pack('{CONTENT_FIRST[cat]}'," in query,
              f"the Content block of the {cat} rule must lead with {CONTENT_FIRST[cat]}")
        check('strcat("https://platform.socradar.com/app/company/", CompanyId, '
              '"/alarm-management?tab=approved&field=alarmId&operator=equals&value=", AlarmId)' in query,
              "AlarmUrl must open the alarm in the platform (field=alarmId ... value=<id>), the shape Sync parses")
        check(len(query) < 9000, f"the query is {len(query)} characters; the platform limit is 10000")
        check("MonitoredAsset = tostring(AlarmPayload['alarm_asset'])" in query,
              "MonitoredAsset must come from alarm_asset")

        if cat in ("Phishing", "Other"):
            check("pack('Suspicious Domain', SuspiciousDomain," in query,
                  "the Content block must show the extracted phishing domain first, not the payload key")
            check('extract(@"Phishing Domain:\\s*([^\\s,;]+\\.[^\\s,;]+)", 1, AlarmText)' in query
                  and 'trim_end(@"[.,;]+",' in query
                  and "tostring(AlarmPayload['phishing_domain'])" in query and "SuspiciousDomain = tolower(" in query,
                  "SuspiciousDomain must come from the 'Phishing Domain:' line of the alarm text (payload key as fallback)")
            check(cat != "Phishing" or ("SuspiciousDomainLabel = coalesce(SuspiciousDomain, \"n/a\")" in query
                  and props["alertDetailsOverride"]["alertDisplayNameFormat"] == "[SOCRadar] #{{AlarmId}} - {{Title}} - {{SuspiciousDomainLabel}}"),
                  "the title placeholder must be a coalesced label column, never the entity column: an empty "
                  "placeholder value reverts the whole title and loses the #<id> Sync reads")
            # The extraction regex must take only the first token: "Phishing Domain: foo.com,bar.com"
            # used to become one invalid DNS value. Run the very regex the rule carries.
            m_dom = re.search(r'extract\(@"(Phishing Domain:[^"]+)", 1, AlarmText\)', query)
            check(m_dom is not None, "could not find the Phishing Domain extraction in the rule query")
            if m_dom:
                dom_re = m_dom.group(1)
                for text, want in (("Phishing Domain: foo.com,bar.com Score: 80", "foo.com"),
                                   ("Phishing Domain: a.example;b.example x", "a.example"),
                                   ("Phishing Domain: evil-example.com Score: 1", "evil-example.com"),
                                   ("Phishing Domain: evil-example.com. Score: 1", "evil-example.com."),
                                   # 17 of 60 real State Change alarms start like this: no domain, a change label
                                   ("Phishing Domain: Favicon Hash Old Value: 123 New Value: 456", None),
                                   ("Phishing Domain: Content Old Value: a New Value: b", None)):
                    hit = re.search(dom_re, text)
                    got = hit.group(1) if hit else None
                    check(got == want, f"Phishing Domain regex on {text!r} gave {got!r}, want {want!r}")
        elif cat != "Other":
            check("SuspiciousDomain" not in query,
                  "only the phishing rule and the catch-all may derive a suspicious domain")
        if cat == "Credential":
            # The exposed credential is third-party personal data: it must never be copied into an alert.
            check("credential_details" not in query and "username" not in query,
                  "the credential rule must not read the exposed credential itself")
            # CredentialOrigin says WHO the credential belongs to; whether a machine is known is
            # HasMachineInfo. A machine word in the title must not change the origin.
            for text, main, want in (("Customer Credential - No Machine Information", "Deep&Dark Web Monitoring", "Customer"),
                                     ("Employee Credential in Combolists", "Deep&Dark Web Monitoring", "Employee"),
                                     ("Compromised Employee Credential from Infected Machine Detected in Dark Market", "Deep&Dark Web Monitoring", "Employee"),
                                     ("Compromised Customer Credential from Infected Machine Detected in Dark Market", "Deep&Dark Web Monitoring", "Customer"),
                                     ("Machine Information Found for Previously Leaked Credential", "Botnet", "Botnet"),
                                     ("Possible Employee Account for Sale in Russian Blackmarket", "Deep&Dark Web Monitoring", "Employee"),
                                     ("Historical Botnet Intelligence", "Deep&Dark Web Monitoring", "Historical"),
                                     ("VPN Account", "Deep&Dark Web Monitoring", "VPN"),
                                     ("Something New", "Deep&Dark Web Monitoring", "Other")):
                check(origin_of(query, text, main) == want, f"CredentialOrigin of {text!r} must be {want}")
            check("HasMachineInfo = tostring(isnotempty(MachineName) or isnotempty(DeviceIp))" in query,
                  "HasMachineInfo is true when either the machine or its IP is known")
            for arg, cases in (("tostring(AlarmPayload['device_ip'])",
                                (("198.51.100.23", "198.51.100.23"), ("198.51.100.23, 10.0.0.1", "198.51.100.23"),
                                 ("203.0.113.9:8080", "203.0.113.9"), ("", None), ("1.2.3", None), ("-", None))),):
                rx = kql_regex(query, arg)
                for text, want in cases:
                    hit = re.search(rx, text) if rx else None
                    check((hit.group(1) if hit else None) == want, f"DeviceIp regex on {text!r} gave {hit.group(1) if hit else None!r}, want {want!r}")
            trim_pat = re.search(r"MachineName = trim\(@\"([^\"]+)\"", query)
            check(trim_pat is not None, "MachineName must be trimmed")
            if trim_pat:
                for text, want in (("-", ""), (" WS-TEST-01 ", "WS-TEST-01"), ("DESKTOP-ABC", "DESKTOP-ABC"), ("", "")):
                    check(kql_trim(trim_pat.group(1), text) == want, f"MachineName trim of {text!r} must be {want!r}")
            check(query.count("substring(MalwareFamily, 0, 120)") == 1 and query.count("substring(AssetMatch, 0, 120)") == 1,
                  "free-text custom details must be capped at 120 characters (2 KB per alert)")
        if cat == "DataLeak":
            check('LeakUrl startswith "http" and LeakUrl !has "socradar.com"' in query,
                  "the leak entity must be a real link and never a SOCRadar platform link")
            check("LeakUrl = coalesce(tostring(AlarmPayload['content_link']), tostring(AlarmPayload['source_link']), "
                  "tostring(AlarmPayload['repository_url']))" in query,
                  "the leak link is the first of content link, source link, repository link")
            check('iff(gettype(AlarmPayload[\'matched_asset\']) == "array", strcat_array(AlarmPayload[\'matched_asset\'], ", "), '
                  "tostring(AlarmPayload['matched_asset']))" in query, "matched assets arrive as a list and must be joined, not dumped as JSON")
            for sub, want in (("Code Repository Data Leak", "CodeRepo"), ("Dark Web Suspicious Content", "DarkWeb"),
                              ("IM Platform Suspicious Content", "IM"), ("Public Storage Leak", "Storage"), ("PII Exposure", "PII")):
                check(f'AlarmSubType =~ "{sub}", "{want}"' in query, f"LeakChannel must map {sub} to {want}")
            for field in ("LeakSource", "AttackType", "MatchedAsset"):
                check(f"{field} = substring({field}, 0, 120)" in query, f"{field} must be capped at 120 characters")
        if cat == "Phishing":
            rx = kql_regex(query, "tostring(AlarmPayload['ip_address'])")
            for text, want in (("203.0.113.7", "203.0.113.7"), ("203.0.113.7, 198.51.100.1", "203.0.113.7"), ("1.2", None), ("", None)):
                hit = re.search(rx, text) if rx else None
                check((hit.group(1) if hit else None) == want, f"SuspiciousIp regex on {text!r} gave {hit.group(1) if hit else None!r}, want {want!r}")
        if cat == "Vulnerability":
            cve = kql_regex(query, "RelatedEntities")
            for text, want in (('[{"key":"CVE","value":"CVE-2026-12345"}]', "CVE-2026-12345"), ("CVE-2026-123", None), ("no cve", None)):
                hit = re.search(cve, text) if cve else None
                check((hit.group(1) if hit else None) == want, f"CVE regex on {text!r} gave {hit.group(1) if hit else None!r}, want {want!r}")
            asset = kql_regex(query, "RelatedAssets")
            for text, want in (('[{"key":"host","value":"192.0.2.10"}]', "192.0.2.10"), ('[{"key":"ip","value":"192.0.2.11"}]', "192.0.2.11"),
                               ('[{"key":"host","value":"3com.example.test"}]', None), ('[{"key":"port","value":443}]', None)):
                hit = re.search(asset, text) if asset else None
                check((hit.group(1) if hit else None) == want, f"scanned-asset regex on {text!r} gave {hit.group(1) if hit else None!r}, want {want!r}")
            cvss = re.search(r"extract\(@'(\"key\":\"CVSS\"[^']+)', 1, RelatedEntities", query)
            check(cvss is not None and re.search(cvss.group(1), '[{"key":"CVSS","value":7.5}]').group(1) == "7.5",
                  "CVSS must be read from the related entities, decimals included")
            ip = kql_regex(query, "tostring(AlarmPayload['ip_address'])")
            for text, want in (("192.0.2.10:443", "192.0.2.10"), ("192.0.2.10", "192.0.2.10"), ("", None)):
                hit = re.search(ip, text) if ip else None
                check((hit.group(1) if hit else None) == want, f"AffectedIp regex on {text!r} gave {hit.group(1) if hit else None!r}, want {want!r}")
            dom = kql_regex(query, "tostring(AlarmPayload['domains'])")
            for text, want in (('["host.example.test"]', "host.example.test"), ("[]", None), ('["a-b.example.co.uk"]', "a-b.example.co.uk")):
                hit = re.search(dom, text) if dom else None
                check((hit.group(1) if hit else None) == want, f"AffectedDomain regex on {text!r} gave {hit.group(1) if hit else None!r}, want {want!r}")
            check("AffectedSoftware = substring(AffectedSoftware, 0, 120)" in query, "AffectedSoftware must be capped at 120 characters")
            soft = re.search(r'AffectedSoftware = trim\(@"([^"]+)"', query)
            check(soft is not None and kql_trim(soft.group(1), "-") == "" and kql_trim(soft.group(1), " Apache ") == "Apache",
                  "AffectedSoftware must drop the '-' blank so it never shows as a value")

        grouping = props.get("incidentConfiguration", {}).get("groupingConfiguration", {})
        check(props.get("incidentConfiguration", {}).get("createIncident") is True, "rule must create incidents")
        # Grouping moved off the URL entity once IoC URL entities were added: two different
        # alarms that happen to share one IoC URL must not merge into one incident. AlarmId
        # is already a unique custom detail per alarm, so group on that instead.
        check(grouping.get("enabled") is True and grouping.get("matchingMethod") == "Selected"
              and grouping.get("groupByEntities") == [] and grouping.get("groupByCustomDetails") == ["AlarmId"],
              "alerts must group into one incident by the AlarmId custom detail (duplicate alerts of one alarm, "
              "without merging unrelated alarms that share an IoC entity)")
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
        derived = set()
        for line in query.split("\n"):
            if line.startswith("| extend "):
                derived |= set(re.findall(r"(?:^\| extend |, )([A-Za-z_]\w*) = ", line))
        missing = columns - declared - derived
        check(not missing, f"rule query projects columns the alarms table does not have: {sorted(missing)}")
        check(set(details.values()) <= columns, "every custom detail must be a projected column")
        # Columns the platform or the query itself needs: the alert severity column, the time column that
        # `order by` reads, and what the description is built from.
        for needed in ("TimeGenerated", "AlarmId", "CompanyId", "AlarmText", "AlarmDate", "AlarmDescription",
                       override.get("alertSeverityColumnName", "SentinelSeverity")):
            check(needed in columns, f"the projection must keep {needed}")
        # Defender prices an incident by MITRE tactics alone (empty -> priority 1). The catch-all has no fixed
        # tactic, so each alert takes its own from the main type, and the rule keeps a union as the fallback.
        if cat == "Other":
            check(override.get("alertTacticsColumnName") == "AlarmTactics" and "AlarmTactics" in columns,
                  "the catch-all must pass a projected AlarmTactics column as alertTacticsColumnName")
            rule_tactics = set(props.get("tactics", []))
            check(0 < len(rule_tactics) <= 5 and props.get("techniques"),
                  "the catch-all keeps a fallback set of 1-5 tactics and its techniques; empty tactics score 1 in Defender")
            sys.path.insert(0, os.path.join(REPO, "tools"))
            from check_analytic_rules import TECHNIQUE_TACTICS
            for technique in props.get("techniques", []):
                check(bool(TECHNIQUE_TACTICS.get(technique, set()) & rule_tactics),
                      f"{technique} needs one of {sorted(TECHNIQUE_TACTICS.get(technique, []))} in the catch-all's tactics; Azure rejects the rule otherwise")
            for main, want in TACTICS_EXPECTED.items():
                got = tactics_of(query, main)
                check(got == want, f"AlarmTactics of {main!r} is {got!r}, want {want!r}")
                check(bool(set((got or "").split(",")) & rule_tactics),
                      f"AlarmTactics of {main!r} shares no tactic with the rule's fallback set {sorted(rule_tactics)}")
            check(tactics_of(query, "x") == "Reconnaissance", "an unknown main type must default to Reconnaissance")
            # Techniques: Defender scores an incident from tactics and techniques, and a rule's own techniques
            # do not reach the incident once a tactics column is used, so the column carries them.
            check(override.get("alertDynamicProperties") == [{"alertProperty": "Techniques", "value": "AlarmTechniques"}]
                  and "AlarmTechniques" in columns,
                  "the catch-all must map the projected AlarmTechniques column to the Techniques alert property")
            for main, want in TECHNIQUES_EXPECTED.items():
                got = techniques_of(query, main)
                check(got == want, f"AlarmTechniques of {main!r} is {got!r}, want {want!r}")
                tactic_set = set((tactics_of(query, main) or "").split(","))
                for technique in (got or "").split(","):
                    check(bool(TECHNIQUE_TACTICS.get(technique, set()) & tactic_set),
                          f"{technique} on {main!r} belongs to {sorted(TECHNIQUE_TACTICS.get(technique, []))}, not to its tactics {sorted(tactic_set)}")
            check(techniques_of(query, "x") == "T1595,T1596", "an unknown main type must get the Reconnaissance techniques")
            for main, sub, want in FIXTURE:
                if want == "Other":
                    check(bool(tactics_of(query, main)), f"({main}, {sub}) reaches the catch-all and needs a tactic")
        else:
            check("alertTacticsColumnName" not in override and "alertDynamicProperties" not in override and "AlarmTactics" not in query,
                  f"the {cat} rule has a fixed tactic set and must not use the dynamic tactics column")
        block = query[query.index("| extend MonitoredAsset"):query.index("| extend IoCUrl1")]
        pack_line = re.search(r"\| extend AlarmContent = pack\(.*", query).group(0)
        got_pin = [hashlib.sha256(block.encode()).hexdigest()[:20], hashlib.sha256(pack_line.encode()).hexdigest()[:20]]
        if "--pins" in sys.argv:
            print("PIN", cat, got_pin)
        check(got_pin == BLOCK_PINS[cat], f"the {cat} rule's extend block or Content pack changed; behaviour tests passed "
              "but the change is unreviewed (run with --pins after an intended edit)")
        mapped = {m["fieldMappings"][0]["columnName"] for m in mappings}
        check(mapped <= columns, f"every entity column must be projected: {sorted(mapped - columns)}")
        used = set(re.findall(r"\{\{(\w+)\}\}", override.get("alertDisplayNameFormat", "") + override.get("alertDescriptionFormat", "")))
        check(used <= columns, f"every title/description placeholder must be projected, or the alert reverts to the default text: {sorted(used - columns)}")

        # ARM would read a string that starts with [ and ends with ] as an expression, and the
        # Content Hub packaging tool escapes such strings (EXP-AZURE-0161). None may exist here.
        bracketed = [s for s in strings(rule) if s.startswith("[") and s.endswith("]") and not s.startswith("[concat")
                     and not s.startswith("[resourceId") and not s.startswith("[guid")
                     and s != rule["properties"].get("enabled")]  # the on/off switch is an expression on purpose
        check(not bracketed, f"rule carries literal strings that ARM would parse as expressions: {bracketed[:2]}")

    _context[0] = "rule set"
    # --- the five rules form one exhaustive, exclusive set
    queries = {c: r["properties"]["query"] for c, r in by_cat.items()}
    if len(queries) == 5:
        def between(q, start, end):
            i = q.index(start)
            return q[i:q.index(end, i) + len(end)] if end else q[i:]
        for part, start, end in (
                ("classifier", "// One label per alarm", '"Other")'),
                ("head (dedup, window, link, severity)", "// One alert per alarm.", "| extend SentinelSeverity"),
                ("description body", "| mv-apply ContentKey", "| extend AlarmDescription = iff"),
                ("tail", "| order by TimeGenerated asc", None)):
            texts = {between(q, start, end) for q in queries.values()}
            check(len(texts) == 1, f"the {part} must be byte-identical in all five rules, found {len(texts)} variants")
        for cat, q in queries.items():
            for main, sub, want in FIXTURE:
                check(classify(q, main, sub) == want,
                      f"{cat} rule's classifier puts ({main}, {sub}) in {classify(q, main, sub)}, want {want}")
        # Exclusive: each rule keeps only its own label; exhaustive: the default label is the catch-all's.
        check(all(f'| where AlarmCategory == "{c}"' in q for c, q in queries.items()),
              "each rule must keep exactly its own AlarmCategory")
        check({classify(queries["Other"], "x", "y")} == {"Other"}, "an unknown type must fall to Other")
        # the DCR keeps every payload key the rules read
        dcr_kql = " ".join(json.dumps(r["properties"]["dataFlows"]) for r in root["resources"]
                           if r["type"] == "Microsoft.Insights/dataCollectionRules" and "AlarmsDcrName" in r["name"])
        infra_kql = " ".join(json.dumps(r["properties"]["dataFlows"]) for r in load(os.path.join(
            REPO, "Playbooks", "SOCRadar-Alarms-Infrastructure", "azuredeploy.json"))["resources"]
            if r["type"] == "Microsoft.Insights/dataCollectionRules" and "AlarmsDcrName" in r["name"])
        check(dcr_kql == infra_kql, "the alarms DCR transform differs between azuredeploy.json and the infrastructure template")
        kept = set(re.findall(r"'(\w+)', (?:substring\(tostring\()?AlarmPayload\[", dcr_kql))
        for cat, q in queries.items():
            used = set(re.findall(r"AlarmPayload\['(\w+)'\]", q))
            check(used <= kept, f"{cat} rule reads payload keys the DCR transform drops: {sorted(used - kept)}")
        check("credential_details" not in dcr_kql and "username" not in dcr_kql,
              "the DCR transform must not keep the exposed credential itself")
    ids = root["variables"]
    check(ids.get("alertBackedRuleId") == "[guid(variables('workspaceResourceId'), 'socradar-alert-backed-rule')]",
          "the catch-all must keep the original rule id, or an upgrade adds a second rule for the same alarms")
    seeds = [re.search(r"'([\w-]+)'\)\]$", ids.get(v, "")) for v in RULE_IDS.values()]
    check(all(seeds) and len({m.group(1) for m in seeds}) == 5, "the five rule ids must come from five different guid seeds")
    for cat, found in by_cat.items():
        check(found["name"] == "[concat(parameters('WorkspaceName'), '/Microsoft.SecurityInsights/', variables('%s'))]" % RULE_IDS[cat],
              f"the {cat} rule must be named by its own id variable")
    check(len({r["properties"]["displayName"] for r in rules}) == 5, "the five rules need five different display names")
    for path, template in ((ROOT, root), (IMPORT, import_pb)):
        credential = template["parameters"].get("EnableCredentialRule", {})
        check(credential.get("type") == "bool" and credential.get("defaultValue") is True,
              f"{rel(path)}: EnableCredentialRule must be a bool defaulting to true")
        check(all(template["variables"].get(v) == ids.get(v) for v in RULE_IDS.values()),
              f"{rel(path)}: the rule id variables differ from azuredeploy.json")
    _context[0] = ""

    if autos:
        auto = autos[0]["properties"]
        check(auto.get("order") == 1, "automation rule must declare order")
        try:
            check(eval_switch(auto.get("triggeringLogic", {}).get("isEnabled"), "Direct", True) is False
                  and eval_switch(auto.get("triggeringLogic", {}).get("isEnabled"), "AlertBacked", True) is True,
                  "the labeling automation rule must be on in AlertBacked and off in Direct")
        except ValueError:
            check(False, "the labeling automation rule is switched by an expression this test cannot read")
        logic = auto.get("triggeringLogic", {})
        check(logic.get("triggersOn") == "Incidents" and logic.get("triggersWhen") == "Created",
              "automation rule must trigger on incident creation")
        conditions = logic.get("conditions", [])
        cond_props = conditions[0]["conditionProperties"] if conditions else {}
        check(len(conditions) == 1 and cond_props.get("propertyName") == "IncidentRelatedAnalyticRuleIds"
              and cond_props.get("operator") == "Contains",
              "automation rule must match incidents of these rules by IncidentRelatedAnalyticRuleIds Contains <rule ids>")
        for var in RULE_IDS.values():
            check(sum(f"variables('{var}')" in v for v in cond_props.get("propertyValues", [])) == 1,
                  f"automation rule must list the {var} rule exactly once, or Sync never finds that rule's incidents")
        check(len(cond_props.get("propertyValues", [])) == 5, "automation rule must list exactly the five rule ids")
        actions = auto.get("actions", [])
        check(len(actions) == 1 and actions[0]["actionType"] == "ModifyProperties"
              and actions[0]["actionConfiguration"].get("labels") == [{"labelName": "SOCRadar"}],
              "automation rule must add exactly the SOCRadar label: it is what Sync filters on")
        for var in RULE_IDS.values():
            check(any(f"variables('{var}')" in d for d in autos[0].get("dependsOn", [])),
                  f"automation rule must depend on the {var} rule")

    _context[0] = "sample automation rules"
    orders = sorted([autos[0]["properties"].get("order")] + [a["properties"].get("order") for a in samples]) if autos else []
    check(orders == [1, 2, 3], f"the labeler and the two samples need orders 1, 2, 3: got {orders}")
    for a in samples:
        check(a.get("condition") == "[and(parameters('DeploySampleAutomationRules'), equals(parameters('IncidentMode'), 'AlertBacked'))]",
              "a sample automation rule must be conditional on DeploySampleAutomationRules and on AlertBacked")
        check(a["properties"]["triggeringLogic"]["triggersOn"] == "Incidents"
              and a["properties"]["triggeringLogic"]["triggersWhen"] == "Created", "a sample must trigger on incident creation")
        check(all(act["actionType"] == "ModifyProperties" for act in a["properties"]["actions"]),
              "a sample may only modify incident properties")
        check(all("SOCRadar" != lab["labelName"] for act in a["properties"]["actions"]
                  for lab in act["actionConfiguration"].get("labels", [])),
              "a sample must not add the SOCRadar label: Sync finds incidents through the labeler, not a sample")
    for a in samples:
        conds = a["properties"]["triggeringLogic"]["conditions"][0]["conditionProperties"]
        acts = a["properties"]["actions"][0]["actionConfiguration"]
        if conds.get("propertyName") == "IncidentRelatedAnalyticRuleIds":
            check(len(conds["propertyValues"]) == 1 and "alertBackedPhishingRuleId" in conds["propertyValues"][0],
                  "the phishing sample must match the phishing rule's incidents only")
            check(acts.get("severity") == "High" and acts.get("labels") == [{"labelName": "SOCRadar-Phishing"}],
                  "the phishing sample raises severity to High and adds SOCRadar-Phishing")
        else:
            # A custom-detail condition must be a PropertyArray of type CustomDetails (live: a bare
            # IncidentCustomDetailsKey is rejected, and a Key inside CustomDetailValues is rejected too).
            full = a["properties"]["triggeringLogic"]["conditions"][0]
            items = full.get("conditionProperties", {}).get("itemConditions", [])
            check(full.get("conditionType") == "PropertyArray"
                  and full["conditionProperties"].get("arrayType") == "CustomDetails"
                  and full["conditionProperties"].get("arrayConditionType") == "AnyItem"
                  and [(i["conditionProperties"]["propertyName"], i["conditionProperties"]["operator"], i["conditionProperties"]["propertyValues"]) for i in items]
                  == [("IncidentCustomDetailsKey", "Equals", ["SuspiciousDomain"])],
                  "the custom-detail sample must test that the SuspiciousDomain custom detail exists")
            check(acts.get("labels") == [{"labelName": "SOCRadar-SuspiciousDomain"}], "the custom-detail sample adds SOCRadar-SuspiciousDomain")
    for path, template in ((ROOT, root), (IMPORT, import_pb)):
        sample_param = template["parameters"].get("DeploySampleAutomationRules", {})
        check(sample_param.get("type") == "bool" and sample_param.get("defaultValue") is False,
              f"{rel(path)}: DeploySampleAutomationRules must be a bool defaulting to false")
    _context[0] = ""

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

        IOC_COLUMNS = ["IoCIp1", "IoCDomain1", "IoCUrl1"]
        _, ingest = by_name(actions, "Ingest_Alarm_Row")
        _, direct_ingest = by_name(actions, "Ingest_To_Custom_Table")
        ingest_cols = list(ingest["inputs"]["body"][0].keys()) if ingest else []
        direct_cols = list(direct_ingest["inputs"]["body"][0].keys()) if direct_ingest else []
        # AlertBacked writes every Direct-mode column plus the first IP/domain/URL IoC (its own
        # entity mappings, since the alert-backed path cannot run Direct's bookmark-based
        # enrichment). One per type, not three: a live deploy measured the real entityMappings
        # cap at 5, so only 4 of 5 are spent here (AlarmUrl + these 3).
        check(ingest and ingest["inputs"]["method"] == "POST" and direct_cols
              and all(c in ingest_cols for c in direct_cols)
              and [c for c in ingest_cols if c not in direct_cols] == IOC_COLUMNS,
              f"{label}: Ingest_Alarm_Row must write every Direct-mode column plus exactly the 3 IoC columns")
        for i, col in enumerate(("ips", "domains", "urls")):
            name = IOC_COLUMNS[i]
            check(ingest and ingest["inputs"]["body"][0].get(name)
                  == f"@{{coalesce(outputs('Parse_AlertBacked_IoC_Arrays')?['{col}']?[0], '')}}",
                  f"{label}: {name} must read Parse_AlertBacked_IoC_Arrays['{col}'][0], defaulting to ''")
        _, parse = by_name(actions, "Parse_AlertBacked_IoC_Arrays")
        check(parse and ingest and ingest["runAfter"] == {"Parse_AlertBacked_IoC_Arrays": ["Succeeded"]},
              f"{label}: Ingest_Alarm_Row must run after Parse_AlertBacked_IoC_Arrays")
        _, run_regex = by_name(actions, "Run_AlertBacked_IoC_Regex_Query")
        check(parse and run_regex and set(parse["runAfter"].get("Run_AlertBacked_IoC_Regex_Query", []))
              == {"Succeeded", "Failed", "TimedOut"},
              f"{label}: Parse_AlertBacked_IoC_Arrays must run regardless of the regex call's outcome "
              "(enrichment failures must never block ingestion)")
        check(run_regex and "retryPolicy" in run_regex["inputs"],
              f"{label}: Run_AlertBacked_IoC_Regex_Query must declare its retryPolicy inside inputs")
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

    # Severity: the label reader stays first; when it is empty the level comes from the
    # description the alert-backed rule wrote. The rank reads the resolved value only.
    _, from_desc = by_name(actions, "Severity_From_Description")
    check(from_desc is not None and "?['properties']?['description']" in from_desc["inputs"],
          f"{label}: Severity_From_Description must read the incident description")
    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        check(from_desc is not None and f"'{SEVERITY_MARK}{level}'), '{level}'" in from_desc["inputs"],
              f"{label}: Severity_From_Description must map '{SEVERITY_MARK}{level}' to {level}")
    check(from_desc is not None and from_desc["inputs"].rstrip().endswith(", '')))))"),
          f"{label}: Severity_From_Description must fall back to '' (unknown -> rank 0)")
    check(from_desc is not None and from_desc["runAfter"] == {"Extract_SOCRadar_Severity": ["Succeeded"]},
          f"{label}: Severity_From_Description must follow the label reader")
    _, resolve_sev = by_name(actions, "Resolve_SOCRadar_Severity")
    check(resolve_sev is not None and resolve_sev["inputs"] ==
          "@if(empty(outputs('Extract_SOCRadar_Severity')), outputs('Severity_From_Description'), "
          "outputs('Extract_SOCRadar_Severity'))",
          f"{label}: Resolve_SOCRadar_Severity must prefer the label and fall back to the description")
    check(resolve_sev is not None and resolve_sev["runAfter"] == {"Severity_From_Description": ["Succeeded"]},
          f"{label}: Resolve_SOCRadar_Severity must follow Severity_From_Description")
    _, rank = by_name(actions, "Rank_SOCRadar_Severity")
    check(rank is not None and rank["inputs"].count("outputs('Resolve_SOCRadar_Severity')") == 5
          and "outputs('Extract_SOCRadar_Severity')" not in rank["inputs"],
          f"{label}: Rank_SOCRadar_Severity must rank the resolved severity, not the label alone")
    check(rank is not None and rank["runAfter"] == {"Resolve_SOCRadar_Severity": ["Succeeded"]},
          f"{label}: Rank_SOCRadar_Severity must follow Resolve_SOCRadar_Severity")
    # One marker, two writers (rule query and Sync reader): they must agree (EXP-AZURE-0178).
    rule_query = next(r for r in nested_rule(root)["properties"]["template"]["resources"]
                      if r["type"].endswith("/alertRules"))["properties"]["query"]
    check(SEVERITY_MARK in rule_query and from_desc is not None and SEVERITY_MARK in from_desc["inputs"],
          f"{label}: the severity marker text must be identical in the rule query and in Sync")

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
