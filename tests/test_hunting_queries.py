#!/usr/bin/env python3
"""The hunting queries must only read columns the deployment actually creates.

The custom tables in this repo do not store the raw alarm. A data collection rule
transform keeps a fixed allow-list of fields and drops everything else, and the table
resource declares a fixed column list. A hunting query that names a column outside that
list deploys without complaint and then returns nothing forever, or fails to resolve at
query time. Neither shows up in a template validation, so the contract is checked here.

The queries themselves come from the shipped Content Hub package, unchanged, so the
standalone deployment and the Content Hub solution surface the same five hunts.

Run:  python3 tests/test_hunting_queries.py
"""

import json
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT = os.path.join(REPO, "azuredeploy.json")

# Tables Microsoft Sentinel provides. Their schemas are not ours to check.
BUILTIN_TABLES = {"SecurityIncident", "SecurityAlert", "AzureDiagnostics"}

# KQL words that are not column references.
KQL_WORDS = {
    "where", "project", "summarize", "order", "by", "asc", "desc", "extend", "take",
    "top", "join", "kind", "on", "let", "and", "or", "not", "in", "has", "contains",
    "startswith", "endswith", "distinct", "count", "countif", "bin", "ago", "render",
    "timechart", "barchart", "strcat", "extract", "tostring", "toupper", "tolower",
    "isnotempty", "isempty", "make_list", "make_set", "arg_max", "arg_min", "sum",
    "avg", "min", "max", "dcount", "parse_json", "leftouter", "leftanti", "inner",
    "column_ifexists", "coalesce", "iff", "case", "now", "datetime", "true", "false",
}

failures = []


def load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


root = load(ROOT)

# The column allow-list, read from the template rather than restated here: the table
# resource declares it and the data collection rule has to agree with it.
declared = {}
for resource in root["resources"]:
    if resource.get("type") != "Microsoft.OperationalInsights/workspaces/tables":
        continue
    # The resource name is "[concat(parameters('WorkspaceName'), '/', variables('XTableName'))]";
    # resolve the variable to get the real table name.
    match = re.search(r"variables\('([^']+)'\)", resource["name"])
    table = root["variables"].get(match.group(1)) if match else None
    if table is None:
        failures.append(f"could not resolve the table name for {resource['name']}")
        continue
    declared[table] = [c["name"] for c in resource["properties"]["schema"]["columns"]]

if len(declared) < 2:
    failures.append(f"expected at least 2 custom tables, resolved {sorted(declared)} - this check has gone blind")

# The data collection rule must not narrow the table further: a column the table declares
# but the transform drops is a column that is always empty.
for resource in root["resources"]:
    if resource.get("type") != "Microsoft.Insights/dataCollectionRules":
        continue
    for stream, decl in (resource["properties"].get("streamDeclarations") or {}).items():
        stream_columns = {c["name"] for c in decl["columns"]}
        for table, columns in declared.items():
            if set(columns) == stream_columns:
                break
        else:
            failures.append(f"data collection rule {resource['name']} declares a stream that matches "
                            f"no table schema: {sorted(stream_columns)}")

searches = [r for r in root["resources"]
            if r.get("type") == "Microsoft.OperationalInsights/workspaces/savedSearches"]
if len(searches) != 5:
    failures.append(f"expected 5 hunting queries in azuredeploy.json, found {len(searches)}")

checked_columns = 0
for resource in searches:
    display = resource["properties"].get("displayName", resource["name"])
    query = resource["properties"]["query"]
    table = query.split("\n", 1)[0].strip()

    # 1. Every hunting query is gated, so a cross-resource-group deployment never tries to
    #    create a child of a workspace that lives somewhere else.
    condition = resource.get("condition", "")
    if "isExternalWorkspace" not in condition:
        failures.append(f"{display}: not gated on isExternalWorkspace (condition: {condition or 'none'})")
    if table in declared:
        switch = "EnableAuditLogging" if table.startswith("SOCRadarAudit") else "EnableAlarmsTable"
        if switch not in condition:
            failures.append(f"{display}: reads {table} but is not gated on {switch}")

    if resource["properties"].get("category") != "Hunting Queries":
        failures.append(f"{display}: category is not 'Hunting Queries'")

    # 2. Column contract.
    if table in BUILTIN_TABLES:
        continue
    if table not in declared:
        failures.append(f"{display}: reads {table}, which this deployment does not create")
        continue

    body = re.sub(r'"[^"]*"', '""', query)
    aliases = set(re.findall(r"([A-Za-z_][A-Za-z0-9_]*)\s*=", body))
    tokens = set(re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", body))
    columns = tokens - aliases - KQL_WORDS - {table}
    if not columns:
        failures.append(f"{display}: no column reference found - this check has gone blind")
    for column in sorted(columns):
        checked_columns += 1
        if column not in declared[table]:
            failures.append(f"{display}: reads {table}.{column}, which the table does not declare "
                            f"(declared: {', '.join(declared[table])})")

if checked_columns < 8:
    failures.append(f"only {checked_columns} column references were checked - this check has gone blind")

if failures:
    print("HUNTING QUERY CHECK FAILED\n")
    for item in failures:
        print("  - " + item)
    print(f"\n{len(failures)} problem(s).")
    sys.exit(1)

print(f"{len(searches)} hunting queries, {checked_columns} column references, all declared and gated.")
