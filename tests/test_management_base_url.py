#!/usr/bin/env python3
"""The templates must resolve the Azure Resource Manager host, never hardcode it.

Every ARM URL in this repo used to start with the literal https://management.azure.com.
That works in the Azure public cloud and nowhere else: in Azure Government, Azure China
and any other sovereign cloud the Resource Manager lives on a different host, so the
deployment succeeds, the Logic App runs, and every call to Microsoft Sentinel fails at
run time. Nothing before an actual run catches it, because ARM template validation never
executes a workflow action.

The host now comes from environment().resourceManager. That function returns the value
with a trailing slash in the public cloud, so the variable trims one if it is there and
the URLs keep their own leading slash. Rendered in the public cloud the result is
byte-identical to the literal it replaced.

Run:  python3 tests/test_management_base_url.py
"""

import json
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT = os.path.join(REPO, "azuredeploy.json")
IMPORT = os.path.join(REPO, "Playbooks", "SOCRadar-Alarm-Import", "azuredeploy.json")
SYNC = os.path.join(REPO, "Playbooks", "SOCRadar-Alarm-Sync", "azuredeploy.json")
URL_BUILDERS = [ROOT, IMPORT, SYNC]
ALL_TEMPLATES = URL_BUILDERS + [
    os.path.join(REPO, "Playbooks", "SOCRadar-Alarms-Infrastructure", "azuredeploy.json"),
    os.path.join(REPO, "Playbooks", "SOCRadar-Audit-Infrastructure", "azuredeploy.json"),
    os.path.join(REPO, "Playbooks", "SOCRadar-Workbook", "azuredeploy.json"),
]

# What environment().resourceManager returns in the Azure public cloud, and what the
# variable trims it to.
PUBLIC_CLOUD_HOST = "https://management.azure.com"

failures = []


def rel(path):
    return os.path.relpath(path, REPO)


def load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def strings(node):
    """Yield every string value in a loaded template."""
    if isinstance(node, dict):
        for value in node.values():
            yield from strings(value)
    elif isinstance(node, list):
        for value in node:
            yield from strings(value)
    elif isinstance(node, str):
        yield node


def render(text):
    """Substitute the public-cloud host for both indirections."""
    return (text
            .replace("variables('managementBaseUrl')", "'" + PUBLIC_CLOUD_HOST + "'")
            .replace("@{parameters('ManagementBaseUrl')}", PUBLIC_CLOUD_HOST))


# 1. No template anywhere hardcodes the public cloud host.
for path in ALL_TEMPLATES:
    with open(path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh.read().split("\n"), 1):
            if "https://management.azure.com" in line and "schema.management.azure.com" not in line:
                failures.append(f"{rel(path)}:{lineno}: hardcoded ARM host")

# 2. The variable exists, is the same everywhere, and handles both forms of the
#    environment() return value. A plain substring() would eat a character in a cloud
#    whose resourceManager has no trailing slash.
expressions = {rel(p): load(p).get("variables", {}).get("managementBaseUrl") for p in URL_BUILDERS}
if None in expressions.values():
    failures.append("managementBaseUrl missing: " + json.dumps(expressions))
elif len(set(expressions.values())) != 1:
    failures.append("managementBaseUrl differs between templates: " + json.dumps(expressions, indent=2))
else:
    expression = next(iter(expressions.values()))
    for fragment in ("environment().resourceManager", "endsWith(", "substring("):
        if fragment not in expression:
            failures.append(f"managementBaseUrl does not use {fragment}: {expression}")

# 3. Rendered in the public cloud, every ARM URL is still well formed. A missing or
#    doubled slash is the failure this rewrite could plausibly introduce.
for path in URL_BUILDERS:
    for text in strings(load(path)):
        if "managementBaseUrl" not in text and "ManagementBaseUrl" not in text:
            continue
        rendered = render(text)
        if PUBLIC_CLOUD_HOST + "//" in rendered:
            failures.append(f"{rel(path)}: doubled slash after the host: {rendered[:140]}")
        # Outside the variable declaration itself, the host must be followed by a path
        # separator or by an expression that supplies one.
        if text == expression:
            continue
        for match in re.finditer(re.escape(PUBLIC_CLOUD_HOST), rendered):
            tail = rendered[match.end():match.end() + 2]
            if tail[:1] not in ("/", "@", '"', "'", ""):
                failures.append(f"{rel(path)}: host is not followed by a path separator: {rendered[:140]}")

# 4. Every workflow that uses the parameter declares it and is handed a value.
for path in URL_BUILDERS:
    for resource in load(path).get("resources", []):
        if resource.get("type") != "Microsoft.Logic/workflows":
            continue
        definition = resource["properties"]["definition"]
        used = "ManagementBaseUrl" in json.dumps(definition.get("actions", {}))
        declared = (definition.get("parameters") or {}).get("ManagementBaseUrl")
        supplied = (resource["properties"].get("parameters") or {}).get("ManagementBaseUrl")
        if used and not declared:
            failures.append(f"{rel(path)}: workflow uses ManagementBaseUrl but does not declare it")
        if used and supplied != {"value": "[variables('managementBaseUrl')]"}:
            failures.append(f"{rel(path)}: ManagementBaseUrl is not wired to the variable: {supplied}")
        if declared and not used:
            failures.append(f"{rel(path)}: ManagementBaseUrl is declared but unused")

# 5. The incident title and the query that looks incidents up again must agree on the
#    same prefix. Rewriting the lines that carry that prefix is how the duplicate-import
#    bug was introduced once before (EXP-AZURE-0161), and this rewrite touches exactly
#    those lines.
for path in (ROOT, IMPORT):
    blob = json.dumps(load(path))
    filters = set(re.findall(r"startswith\(properties/title, ''(.*?)''\)", blob))
    titles = set(re.findall(r'"title": "([^"]*?)#', blob))
    if not filters:
        failures.append(f"{rel(path)}: no title filter found - this check has gone blind")
    if not titles:
        failures.append(f"{rel(path)}: no incident title found - this check has gone blind")
    for prefix in filters:
        for title in titles:
            if not title.startswith(prefix):
                failures.append(f"{rel(path)}: incident title {title!r} does not start with the "
                                f"filter prefix {prefix!r} - imports would duplicate")

if failures:
    print("MANAGEMENT BASE URL CHECK FAILED\n")
    for item in failures:
        print("  - " + item)
    print(f"\n{len(failures)} problem(s).")
    sys.exit(1)

print("ARM host is resolved from environment().resourceManager in every template.")
