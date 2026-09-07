#!/usr/bin/env python3
"""How far back a run looks must come from a checkpoint, not from incident titles.

The import playbook used to ask Microsoft Sentinel for its own newest incident and
derive the lookback window from that incident's creation time. The query it used is
startswith(properties/title, '[SOCRadar]'), so the window silently depended on the
incident title staying in the shape this playbook writes it. Three separate places
read that title, and an analytics rule that produces incidents with a different title
puts the playbook on the initial 600-minute window for the rest of its life.

The window now comes from a row in Azure Table Storage that the run writes itself,
and the alarm id also rides on the incident as a label so the sync playbook no longer
has to parse the title to find it. Both replacements have a failure mode that only
appears at run time:

  - the checkpoint row does not exist on the first run of a fresh deployment, so the
    read returns 404 and Determine_Lookback has to be allowed to run after a failure
  - the checkpoint may only advance when the import actually read every page, or a
    half-finished run moves the window past alarms it never saw

Run:  python3 tests/test_checkpoint.py
"""

import json
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT = os.path.join(REPO, "azuredeploy.json")
IMPORT = os.path.join(REPO, "Playbooks", "SOCRadar-Alarm-Import", "azuredeploy.json")
SYNC = os.path.join(REPO, "Playbooks", "SOCRadar-Alarm-Sync", "azuredeploy.json")

STORAGE_TABLE_DATA_CONTRIBUTOR = "0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3"
# uniqueString() returns 13 characters. A storage account name may be at most 24.
UNIQUE_STRING_LENGTH = 13
MAX_ACCOUNT_NAME = 24

failures = []
checks = 0


def rel(path):
    return os.path.relpath(path, REPO)


def load(path):
    with open(path) as fh:
        return json.load(fh)


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


def workflows(template):
    for resource in template.get("resources", []):
        if resource.get("type") == "Microsoft.Logic/workflows":
            yield resource


def actions_of(resource):
    return walk(resource["properties"]["definition"]["actions"])


def find(actions, name):
    for key, body in actions.items():
        if key.split("/")[-1] == name:
            return key, body
    return None, None


def check(condition, message):
    global checks
    checks += 1
    if not condition:
        failures.append(message)


# --- the storage the checkpoint lives in ------------------------------------------------
# Both templates create it themselves. The root template is deployed on its own and the
# import playbook is deployed on its own, so neither can rely on the other's resources.
for path in (ROOT, IMPORT):
    template = load(path)
    variables = template.get("variables", {})
    name_expression = variables.get("checkpointStorageAccountName", "")
    check(name_expression != "", f"{rel(path)}: no checkpointStorageAccountName variable")

    # A storage account name is global, lowercase alphanumeric and at most 24 characters.
    # Deployment fails outright on a longer one, so the length is computed here rather
    # than left for a live deployment to discover.
    prefix = name_expression.split("concat('", 1)[-1].split("'", 1)[0] if "concat('" in name_expression else ""
    check(prefix.isalnum() and prefix.islower(),
          f"{rel(path)}: storage account prefix {prefix!r} is not lowercase alphanumeric")
    check(len(prefix) + UNIQUE_STRING_LENGTH <= MAX_ACCOUNT_NAME,
          f"{rel(path)}: storage account name renders to {len(prefix) + UNIQUE_STRING_LENGTH} "
          f"characters, over the {MAX_ACCOUNT_NAME} limit")
    check("uniqueString(" in name_expression,
          f"{rel(path)}: storage account name is not derived from uniqueString, so two "
          f"deployments in different resource groups could collide")

    # The table URL carries the cloud's own storage suffix. A literal core.windows.net
    # would deploy fine and then fail every read in a sovereign cloud.
    url = variables.get("checkpointTableUrl", "")
    check("environment().suffixes.storage" in url,
          f"{rel(path)}: checkpointTableUrl does not use environment().suffixes.storage")
    check("core.windows.net" not in url,
          f"{rel(path)}: checkpointTableUrl hardcodes core.windows.net")

    accounts = [r for r in template["resources"] if r["type"] == "Microsoft.Storage/storageAccounts"]
    check(len(accounts) == 1, f"{rel(path)}: expected exactly one storage account, found {len(accounts)}")
    if accounts:
        properties = accounts[0].get("properties", {})
        # The playbook authenticates with its managed identity. Leaving shared keys enabled
        # would hand anyone who reads the account keys a way in that no role assignment gates.
        check(properties.get("allowSharedKeyAccess") is False,
              f"{rel(path)}: storage account still allows shared key access")
        check(properties.get("supportsHttpsTrafficOnly") is True,
              f"{rel(path)}: storage account allows plain HTTP")
        check(properties.get("minimumTlsVersion") == "TLS1_2",
              f"{rel(path)}: storage account does not require TLS 1.2")
        check(properties.get("allowBlobPublicAccess") is False,
              f"{rel(path)}: storage account allows anonymous blob access")

    tables = [r for r in template["resources"]
              if r["type"] == "Microsoft.Storage/storageAccounts/tableServices/tables"]
    check(len(tables) == 1, f"{rel(path)}: expected exactly one checkpoint table, found {len(tables)}")

    # Without this role assignment every read and write is a 403, and the run reports
    # success while the window never moves.
    check(variables.get("StorageTableDataContributorRoleId") == STORAGE_TABLE_DATA_CONTRIBUTOR,
          f"{rel(path)}: StorageTableDataContributorRoleId is not the Storage Table Data "
          f"Contributor role id ({variables.get('StorageTableDataContributorRoleId')})")
    grants = [r for r in template["resources"]
              if r["type"] == "Microsoft.Authorization/roleAssignments"
              and "StorageTableDataContributorRoleId" in json.dumps(r)]
    check(len(grants) == 1,
          f"{rel(path)}: expected one Storage Table Data Contributor assignment, found {len(grants)}")
    if grants:
        grant = grants[0]
        check("Microsoft.Storage/storageAccounts'" in grant.get("scope", ""),
              f"{rel(path)}: the storage role assignment is not scoped to the storage account "
              f"({grant.get('scope')})")
        check(grant["properties"].get("principalType") == "ServicePrincipal",
              f"{rel(path)}: the storage role assignment does not declare principalType")
        check("Microsoft.Logic/workflows" in grant["properties"].get("principalId", ""),
              f"{rel(path)}: the storage role assignment does not grant the playbook's own identity")


# --- the read, the write and the window ------------------------------------------------
for path in (ROOT, IMPORT):
    template = load(path)
    for resource in workflows(template):
        actions = actions_of(resource)
        if find(actions, "Determine_Lookback")[1] is None:
            continue

        # The probe this replaces has to be gone, not merely unused: while it is still in
        # the definition the playbook keeps a dependency on its own incident titles.
        check("Query_Existing_SOCRadar_Incidents" not in json.dumps(resource),
              f"{rel(path)}: the incident-title lookback probe is still in the definition")

        _, read = find(actions, "Read_Checkpoint")
        check(read is not None, f"{rel(path)}: no Read_Checkpoint action")
        if read:
            inputs = read["inputs"]
            check(inputs["method"] == "GET", f"{rel(path)}: Read_Checkpoint is not a GET")
            check(inputs["authentication"]["type"] == "ManagedServiceIdentity",
                  f"{rel(path)}: Read_Checkpoint does not authenticate with the managed identity")
            check(inputs["authentication"].get("audience") == "https://storage.azure.com",
                  f"{rel(path)}: Read_Checkpoint asks for the wrong token audience "
                  f"({inputs['authentication'].get('audience')})")
            # Table Storage answers a request without these headers with 415, not with data.
            check(inputs["headers"].get("Accept") == "application/json;odata=nometadata",
                  f"{rel(path)}: Read_Checkpoint is missing the odata=nometadata Accept header")
            check("x-ms-version" in inputs["headers"],
                  f"{rel(path)}: Read_Checkpoint does not pin the Table Storage API version")

        _, write = find(actions, "Write_Checkpoint")
        check(write is not None, f"{rel(path)}: no Write_Checkpoint action")
        if write:
            inputs = write["inputs"]
            check(inputs["method"] == "PUT",
                  f"{rel(path)}: Write_Checkpoint is not a PUT, so it cannot replace the row")
            check(inputs["headers"].get("Content-Type") == "application/json;odata=noop",
                  f"{rel(path)}: Write_Checkpoint is missing the odata=noop Content-Type header")
            check(inputs["headers"].get("Accept") == "application/json;odata=noop",
                  f"{rel(path)}: Write_Checkpoint is missing the odata=noop Accept header")
            body = inputs.get("body", {})
            for key in ("PartitionKey", "RowKey", "LastRunUtc"):
                check(key in body, f"{rel(path)}: the checkpoint row has no {key}")
            # The stamp is taken at the start of the run, not at the end. A run takes
            # minutes; stamping the end would skip every alarm raised while it worked.
            check("Capture_Run_Start" in json.dumps(body.get("LastRunUtc")),
                  f"{rel(path)}: the checkpoint stores something other than the run start time "
                  f"({body.get('LastRunUtc')})")

        _, start = find(actions, "Capture_Run_Start")
        check(start is not None and "utcNow()" in json.dumps(start.get("inputs")),
              f"{rel(path)}: Capture_Run_Start does not stamp utcNow()")

        # A failed write must not pass unnoticed. The next run falls back to the initial
        # window, so nothing is lost, but the operator has to be able to see it happened.
        _, logged = find(actions, "Log_Checkpoint_Write_Failed")
        check(logged is not None, f"{rel(path)}: a failed checkpoint write is not logged")
        if logged:
            check(logged["runAfter"].get("Write_Checkpoint") == ["Failed"],
                  f"{rel(path)}: the checkpoint failure log does not run after a failed write")

        lookback = find(actions, "Determine_Lookback")[1]
        expression = lookback["inputs"]
        check("Read_Checkpoint" in expression,
              f"{rel(path)}: Determine_Lookback does not read the checkpoint")
        check("LastRunUtc" in expression,
              f"{rel(path)}: Determine_Lookback does not read LastRunUtc")
        check("title" not in expression and "createdTimeUtc" not in expression,
              f"{rel(path)}: Determine_Lookback still derives the window from an incident")
        # A fresh deployment's first read is a 404, so the chain from Read_Checkpoint to
        # Determine_Lookback has to survive a failed read. Before task_azure_0056 that
        # tolerance sat on Determine_Lookback itself, which also swallowed a 5xx and
        # silently shortened the window. Only the guard shape is accepted now: accepting
        # the old one too let a revert of 0056 pass green, because the three assertions
        # below then never ran (task_azure_0057, adversarial review).
        guard = actions.get("Check_Checkpoint_Read")
        check(guard is not None,
              f"{rel(path)}: Check_Checkpoint_Read is gone - a failed checkpoint read is "
              f"no longer told apart from a first run")
        check("Failed" in (guard["runAfter"].get("Read_Checkpoint") or []),
              f"{rel(path)}: Check_Checkpoint_Read does not run after a failed read, so "
              f"the first run of a fresh deployment dies on its 404")
        check("TimedOut" in (guard["runAfter"].get("Read_Checkpoint") or []),
              f"{rel(path)}: Check_Checkpoint_Read does not run after a timed-out read, "
              f"so the run cascade-skips without saying why")
        check("Check_Checkpoint_Read" in lookback["runAfter"],
              f"{rel(path)}: Determine_Lookback no longer waits for the guard")
        check("Read_Checkpoint" not in lookback["runAfter"],
              f"{rel(path)}: Determine_Lookback still tolerates the raw read, which is "
              f"the pre-0056 shape that swallowed a 5xx")
        # And the transient case must NOT look like a first run: a non-404 failure has to
        # raise a flag that stops the checkpoint from moving, or the run silently skips
        # every alarm between the real checkpoint and the shortened window.
        check("404" in json.dumps(guard["expression"]),
              f"{rel(path)}: Check_Checkpoint_Read does not single out 404")
        check("checkpoint_read_failed" in json.dumps(guard.get("else", {})),
              f"{rel(path)}: a failed checkpoint read raises no flag")
        verify = actions.get("Verify_Import_Complete", {})
        check("checkpoint_read_failed" in json.dumps(verify.get("expression", {})),
              f"{rel(path)}: the checkpoint can still be written after a failed read")
        # The operator has to be told which read failed, not just that a page was missed.
        # Fail_Incomplete_Import sits in Verify_Import_Complete's else, not at top level.
        fail = (verify.get("else", {}).get("actions", {})
                     .get("Fail_Incomplete_Import", {}))
        check(bool(fail), f"{rel(path)}: Verify_Import_Complete has no failing else branch")
        fail_msg = json.dumps(fail.get("inputs", {}))
        check("checkpoint_read_failed" in fail_msg,
              f"{rel(path)}: the failure message never mentions the checkpoint read")
        check("incidents_truncated" in fail_msg,
              f"{rel(path)}: the failure message never mentions the truncated dedup list")
        # The clamp is what keeps a stale or absent checkpoint from asking for an unbounded
        # window, and what keeps a fresh one from asking for a window shorter than the
        # polling interval.
        check("10080" in expression, f"{rel(path)}: Determine_Lookback lost its upper clamp")
        check("InitialLookbackMinutes" in expression,
              f"{rel(path)}: Determine_Lookback has no fallback for a missing checkpoint")

        # The table has to exist before the workflow runs, so the workflow depends on it.
        check("checkpointTableName" in json.dumps(resource.get("dependsOn", [])),
              f"{rel(path)}: the workflow does not depend on the checkpoint table")


# --- the alarm id on the incident -------------------------------------------------------
# An incident is created down one of two paths and the alarm id has to survive both.
# Build_Labels feeds the closed-incident REST call, which only runs when ImportAllStatuses
# is on. Build_Tags feeds the managed Microsoft Sentinel connector, which creates every
# incident on the default OPEN-only path. providerIncidentId is not an option for either:
# it was measured live on 2026-09-04 and Azure overwrites the value the connector sends
# with the incident number, so a label is the only carrier that survives.
for path in (ROOT, IMPORT):
    for resource in workflows(load(path)):
        actions = actions_of(resource)
        for action_name, why in (
            ("Build_Labels", "the closed-incident REST call"),
            ("Build_Tags", "the managed connector, which creates every incident by default"),
        ):
            _, built = find(actions, action_name)
            if built is None:
                continue
            expression = built["inputs"]
            check("SOCRadar-Alarm-" in expression,
                  f"{rel(path)}: {action_name} writes no SOCRadar-Alarm- label, so an incident "
                  f"created through {why} leaves the sync playbook nothing but the title to "
                  f"find the alarm id in")
            check("alarm_id" in expression,
                  f"{rel(path)}: the SOCRadar-Alarm- label in {action_name} is not built from alarm_id")

for path in (ROOT, SYNC):
    for resource in workflows(load(path)):
        _, extract = find(actions_of(resource), "Extract_Alarm_ID")
        if extract is None:
            continue
        expression = extract["inputs"]
        check("SOCRadar-Alarm-" in expression and "labels" in expression,
              f"{rel(path)}: Extract_Alarm_ID does not read the alarm id from the labels")
        # Every incident created before this change has no label. Dropping the title
        # fallback would strand all of them: closed forever in Microsoft Sentinel, never
        # written back to SOCRadar.
        check("title" in expression,
              f"{rel(path)}: Extract_Alarm_ID lost the title fallback, so incidents created "
              f"before the label existed would never sync back")

if checks < 60:
    failures.append(f"only {checks} assertions ran - this check has gone blind")

if failures:
    print("CHECKPOINT CHECK FAILED\n")
    for item in failures:
        print("  - " + item)
    print(f"\n{len(failures)} problem(s) in {checks} assertions.")
    sys.exit(1)

print(f"Checkpoint storage, lookback window and alarm-id label verified in {checks} assertions.")
