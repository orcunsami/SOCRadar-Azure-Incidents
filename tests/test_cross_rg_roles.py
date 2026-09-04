#!/usr/bin/env python3
"""The cross-RG role path must grant the import identity the same role the same-RG path does.

When the workspace lives in another resource group, role assignments move into a
nested deployment. That nested copy is easy to forget when the same-RG role logic
changes, and the failure is silent: the deployment succeeds, the import playbook
runs, and only bookmark creation returns 403.

Measured 5 Sep 2026 in a live cross-RG install: with EnableIoCEnrichment=true the
workspace scope carried two Microsoft Sentinel Responder assignments and no
Contributor, because the nested template used sentinelRoleDefinitionId instead of
importSentinelRoleDefinitionId. IoC enrichment was dead in every cross-RG install.

Checks, for the one-click template and the standalone import playbook:
  1. importSentinelRoleDefinitionId exists and elevates on EnableIoCEnrichment.
  2. Every nested role assignment for the import identity uses that variable, in
     both the assignment name (the guid seed) and roleDefinitionId.
  3. The sync identity keeps the plain sentinelRoleDefinitionId (least privilege).
"""

import json
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FILES = (
    "azuredeploy.json",
    os.path.join("Playbooks", "SOCRadar-Alarm-Import", "azuredeploy.json"),
)
IMPORT_VAR = "variables('importSentinelRoleDefinitionId')"
PLAIN_VAR = "variables('sentinelRoleDefinitionId')"

failures = []


def check(cond, msg):
    if not cond:
        failures.append(msg)


def is_import(name):
    return "ImportPlaybookName" in name or "parameters('PlaybookName')" in name


def is_sync(name):
    return "SyncPlaybookName" in name


for rel in FILES:
    path = os.path.join(REPO, rel)
    template = json.loads(open(path, encoding="utf-8").read())

    elevate = template.get("variables", {}).get("importSentinelRoleDefinitionId")
    check(elevate is not None, "%s: importSentinelRoleDefinitionId is missing" % rel)
    if elevate:
        check(
            "EnableIoCEnrichment" in elevate and "SentinelContributorRoleId" in elevate,
            "%s: importSentinelRoleDefinitionId no longer elevates on EnableIoCEnrichment: %s"
            % (rel, elevate),
        )

    nested_import = 0
    for resource in template["resources"]:
        if resource["type"] != "Microsoft.Resources/deployments":
            continue
        inner = resource["properties"]["template"]["resources"]
        for assignment in inner:
            if assignment["type"] != "Microsoft.Authorization/roleAssignments":
                continue
            name = str(assignment["name"])
            role = str(assignment["properties"].get("roleDefinitionId", ""))
            if PLAIN_VAR not in role and IMPORT_VAR not in role:
                continue  # a fixed role such as Log Analytics Reader
            if is_import(name):
                nested_import += 1
                check(
                    IMPORT_VAR in role,
                    "%s: nested import role assignment uses the un-elevated role "
                    "(IoC enrichment would 403 cross-RG): %s" % (rel, role),
                )
                check(
                    IMPORT_VAR in name,
                    "%s: nested import assignment name must be seeded with the same "
                    "role variable it grants, else the name and the grant drift: %s"
                    % (rel, name),
                )
            elif is_sync(name):
                check(
                    IMPORT_VAR not in role,
                    "%s: the sync identity must stay on SentinelRoleLevel, not the "
                    "elevated import role: %s" % (rel, role),
                )

    check(
        nested_import == 1,
        "%s: expected exactly one nested Sentinel role assignment for the import "
        "identity, found %d" % (rel, nested_import),
    )

if failures:
    for line in failures:
        print("FAIL " + line)
    sys.exit(1)
print("cross-RG role elevation: OK (%d templates)" % len(FILES))
