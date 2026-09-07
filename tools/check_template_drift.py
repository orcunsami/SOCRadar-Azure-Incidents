#!/usr/bin/env python3
"""Fail if the standalone Playbooks/ templates drift away from azuredeploy.json.

Ported from Radargoger/SOCRadar-Azure-Incidents (commit b2e58a3) and adapted to this
repo's action names and template set. The one-click template and the standalone
templates hold two hand-maintained copies of the same logic; they can silently drift
apart. This check compares the expressions that carry the behaviour and exits
non-zero when they stop matching.

History of the write-guard check (corrected 2026-09-04):
  - An earlier note here claimed this repo's sync playbook had no named
    "Check_SOCRadar_Write_Succeeded" condition action, and the guard check was
    replaced with a comparison of Add_Synced_Tag's runAfter. That claim was wrong.
    The action does exist, in both the one-click template and the standalone
    playbook, at For_Each_Incident/Check_If_Closed_And_Not_Synced/
    Check_SOCRadar_Write_Succeeded, and Add_Synced_Tag sits inside it. The
    replacement check compared an empty runAfter with an empty runAfter, so it
    could never fail. The original expression comparison is restored below and the
    placement check now names the guard itself.
Run:  python3 tools/check_template_drift.py
"""

import json
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT = os.path.join(REPO, "azuredeploy.json")
IMPORT = os.path.join(REPO, "Playbooks", "SOCRadar-Alarm-Import", "azuredeploy.json")
SYNC = os.path.join(REPO, "Playbooks", "SOCRadar-Alarm-Sync", "azuredeploy.json")
ALARMS_INFRA = os.path.join(REPO, "Playbooks", "SOCRadar-Alarms-Infrastructure", "azuredeploy.json")
AUDIT_INFRA = os.path.join(REPO, "Playbooks", "SOCRadar-Audit-Infrastructure", "azuredeploy.json")

# Every azuredeploy.json in the repo, including the ones not compared below
# (Workbook has no workflow/DCR to drift).
ALL_TEMPLATES = [ROOT, IMPORT, SYNC, ALARMS_INFRA, AUDIT_INFRA,
                  os.path.join(REPO, "Playbooks", "SOCRadar-Workbook", "azuredeploy.json")]


def load(path):
    with open(path) as fh:
        return json.load(fh)


def walk_actions(actions, prefix=""):
    found = {}
    for name, body in actions.items():
        found[prefix + name] = body
        if "actions" in body:
            found.update(walk_actions(body["actions"], prefix + name + "/"))
        branch = body.get("else")
        if isinstance(branch, dict) and "actions" in branch:
            found.update(walk_actions(branch["actions"], prefix + name + "/else/"))
    return found


def workflow_actions(template, want_sync=None):
    """Collect actions from the workflows in a template.

    want_sync None -> every workflow; True -> only the sync playbook; False -> only import.
    The sync playbook is the one that writes back to SOCRadar.
    """
    collected = {}
    for resource in template.get("resources", []):
        if resource.get("type") != "Microsoft.Logic/workflows":
            continue
        actions = walk_actions(resource["properties"]["definition"]["actions"])
        is_sync = any(k.split("/")[-1] == "Update_SOCRadar_Status" for k in actions)
        if want_sync is None or is_sync == want_sync:
            collected.update(actions)
    return collected


def action_field(actions, name, field):
    for key, body in actions.items():
        if key.split("/")[-1] == name:
            value = body.get(field)
            if isinstance(value, str):
                return value
            return json.dumps(value, sort_keys=True)
    return None


def request_body(actions, name):
    for key, body in actions.items():
        if key.split("/")[-1] == name:
            inputs = body.get("inputs") or {}
            return json.dumps(inputs.get("body"), sort_keys=True)
    return None


def run_after(actions, name):
    for key, body in actions.items():
        if key.split("/")[-1] == name:
            return json.dumps(body.get("runAfter"), sort_keys=True)
    return None


def transforms(template):
    out = []
    for resource in template.get("resources", []):
        if resource.get("type") == "Microsoft.Insights/dataCollectionRules":
            for flow in resource["properties"].get("dataFlows", []):
                out.append(flow.get("transformKql"))
    return out


def until_loops(template):
    """Yield (workflow_action_path, until_body) for every Until loop in a template."""
    for resource in template.get("resources", []):
        if resource.get("type") != "Microsoft.Logic/workflows":
            continue
        for path, body in walk_actions(resource["properties"]["definition"]["actions"]).items():
            if body.get("type") == "Until":
                yield path, body


def stalled_progress(until_body):
    """Names of loop actions that a single failed Foreach item would leave Skipped.

    A Foreach reports Failed when any one of its items fails, which is normal when
    the items are independent records. An action that advances the loop must not
    hang off that status, or the loop repeats the same work until it times out.
    See EXP-AZURE-0136 and EXP-AZURE-0156.
    """
    inner = until_body.get("actions", {})
    foreaches = {name for name, body in inner.items() if body.get("type") == "Foreach"}
    stalled = []
    for name, body in inner.items():
        if body.get("type") not in ("IncrementVariable", "SetVariable"):
            continue
        for dependency, statuses in (body.get("runAfter") or {}).items():
            if dependency in foreaches and "Failed" not in statuses:
                stalled.append(f"{name} waits for {dependency} {statuses}")
    return stalled


def unbounded_result_payloads(template):
    """Request bodies that embed result(), which carries every action's inputs+outputs.

    Measured live: one such body reached 1.2 MB and Azure Monitor rejected it with
    RequestEntityTooLarge on 197 of 250 repetitions. See EXP-AZURE-0156.
    """
    offenders = []
    for resource in template.get("resources", []):
        if resource.get("type") != "Microsoft.Logic/workflows":
            continue
        for path, body in walk_actions(resource["properties"]["definition"]["actions"]).items():
            if body.get("type") != "Http":
                continue
            payload = json.dumps((body.get("inputs") or {}).get("body"))
            if "result(" in payload:
                offenders.append(path)
    return offenders


def main():
    root = load(ROOT)
    root_import = workflow_actions(root, want_sync=False)
    root_sync = workflow_actions(root, want_sync=True)
    mod_import = workflow_actions(load(IMPORT))
    mod_sync = workflow_actions(load(SYNC))

    failures = []

    def compare(label, left, right):
        if left is None or right is None:
            failures.append(f"{label}: missing on one side (root={left is not None}, standalone={right is not None})")
        elif left != right:
            failures.append(f"{label}: differs\n    root:       {str(left)[:200]}\n    standalone: {str(right)[:200]}")

    # Import playbook behaviour that has drifted before. Build_Labels is here because the
    # incident's labels are what the sync playbook reads back, so a one-sided change to it
    # silently breaks the return path.
    for name in ("Determine_Lookback", "Extract_Existing_IDs", "Calculate_Epoch_Start",
                 "Build_Labels", "Build_Tags"):
        compare(name, action_field(root_import, name, "inputs"), action_field(mod_import, name, "inputs"))

    # The checkpoint is what decides how far back a run looks. A one-sided change to its
    # URI, its body or the run-start stamp puts the two copies on different windows, and
    # the difference only shows up as silently skipped alarms.
    compare("Read_Checkpoint inputs", action_field(root_import, "Read_Checkpoint", "inputs"),
            action_field(mod_import, "Read_Checkpoint", "inputs"))
    compare("Write_Checkpoint inputs", action_field(root_import, "Write_Checkpoint", "inputs"),
            action_field(mod_import, "Write_Checkpoint", "inputs"))
    compare("Capture_Run_Start", action_field(root_import, "Capture_Run_Start", "inputs"),
            action_field(mod_import, "Capture_Run_Start", "inputs"))

    # A failed read has to be tolerated, but a 404 (no checkpoint yet) and a 403/5xx (we
    # could not look) must not be treated the same. Since task_azure_0056 that split lives
    # in Check_Checkpoint_Read, and Determine_Lookback waits for it. This check asserted
    # the pre-0056 shape until task_azure_0057 and went red the moment 0056 landed; it is
    # rewritten rather than removed so the invariant it guarded still has a gate.
    for label, actions in (("root", root_import), ("standalone", mod_import)):
        guard = json.loads(run_after(actions, "Check_Checkpoint_Read") or "null")
        if guard is None:
            failures.append(f"Check_Checkpoint_Read: missing from the {label} import playbook - "
                            f"a 404 first run and a transient read failure are no longer told apart")
            continue
        if "Failed" not in (guard.get("Read_Checkpoint") or []):
            failures.append(f"Check_Checkpoint_Read: does not run after a failed Read_Checkpoint in "
                            f"the {label} import playbook - the first run would die on its 404")
        after = json.loads(run_after(actions, "Determine_Lookback") or "{}")
        if "Check_Checkpoint_Read" not in after:
            failures.append(f"Determine_Lookback: does not wait for Check_Checkpoint_Read in the "
                            f"{label} import playbook")
        if "Read_Checkpoint" in after:
            failures.append(f"Determine_Lookback: still runs directly after Read_Checkpoint in the "
                            f"{label} import playbook - the pre-0056 shape swallowed a 5xx")

    # The checkpoint may only advance on a complete import. Writing it anywhere else means a
    # half-read run moves the window forward and the alarms it never read are lost for good.
    for label, actions in (("root", root_import), ("standalone", mod_import)):
        placed = [k for k in actions if k.split("/")[-1] == "Write_Checkpoint"]
        if not placed:
            failures.append(f"Write_Checkpoint: not found in the {label} import playbook")
            continue
        if not placed[0].startswith("Verify_Import_Complete/") or "/else/" in placed[0]:
            failures.append(f"Write_Checkpoint: not inside the success branch of Verify_Import_Complete "
                            f"in the {label} import playbook ({placed[0]})")
        after = json.loads(run_after(actions, "Write_Checkpoint") or "{}")
        if after.get("Import_Complete") != ["Succeeded"]:
            failures.append(f"Write_Checkpoint: does not run only after Import_Complete succeeded in the "
                            f"{label} import playbook (runAfter={json.dumps(after)})")

    # Sync playbook: the write bodies must stay identical on both sides.
    for name in ("Update_SOCRadar_Status", "Update_SOCRadar_Severity"):
        compare(name + " body", request_body(root_sync, name), request_body(mod_sync, name))

    # Sync playbook: the gate around the severity write-back. Microsoft Sentinel has no Critical
    # severity, so an ungated write-back lowers a SOCRadar CRITICAL alarm to High on every close.
    # A one-sided change here would leave one copy gated and the other not.
    compare(
        "Check_Severity_Sync_Enabled",
        action_field(root_sync, "Check_Severity_Sync_Enabled", "expression"),
        action_field(mod_sync, "Check_Severity_Sync_Enabled", "expression"),
    )

    # Update_SOCRadar_Severity must sit inside that gate on both sides.
    for label, actions in (("root", root_sync), ("standalone", mod_sync)):
        placed = [k for k in actions if k.split("/")[-1] == "Update_SOCRadar_Severity"]
        if not placed:
            failures.append(f"Update_SOCRadar_Severity: not found in the {label} sync playbook")
        elif "Check_Severity_Sync_Enabled" not in placed[0]:
            failures.append(
                f"Update_SOCRadar_Severity: not inside Check_Severity_Sync_Enabled in the "
                f"{label} sync playbook ({placed[0]})"
            )

    # Sync playbook: the guard that stops a failed SOCRadar write from being marked as
    # synced. Both sides must carry the same condition expression.
    compare(
        "Check_SOCRadar_Write_Succeeded",
        action_field(root_sync, "Check_SOCRadar_Write_Succeeded", "expression"),
        action_field(mod_sync, "Check_SOCRadar_Write_Succeeded", "expression"),
    )

    # Add_Synced_Tag's runAfter must also match, so a change to the ordering mechanism
    # on only one side is caught alongside the expression.
    compare(
        "Add_Synced_Tag runAfter",
        run_after(root_sync, "Add_Synced_Tag"),
        run_after(mod_sync, "Add_Synced_Tag"),
    )

    # Add_Synced_Tag must sit inside the write-succeeded guard on both sides. Naming the
    # guard itself is the point: a tag placed under Check_If_Closed_And_Not_Synced but
    # outside Check_SOCRadar_Write_Succeeded would mark a failed write as synced.
    for label, actions in (("root", root_sync), ("standalone", mod_sync)):
        placed = [k for k in actions if k.split("/")[-1] == "Add_Synced_Tag"]
        if not placed:
            failures.append(f"Add_Synced_Tag: not found in the {label} sync playbook")
        elif "Check_SOCRadar_Write_Succeeded" not in placed[0]:
            failures.append(
                f"Add_Synced_Tag: not inside Check_SOCRadar_Write_Succeeded in the "
                f"{label} sync playbook ({placed[0]})"
            )

    # Alert-backed mode (task_azure_0051): the sequential loop, its mode gate, the checkpoint
    # hold and the Sync entity reader are one behaviour in two hand-maintained copies.
    compare("Check_If_Should_Import", action_field(root_import, "Check_If_Should_Import", "expression"),
            action_field(mod_import, "Check_If_Should_Import", "expression"))
    for field in ("actions", "runtimeConfiguration", "foreach", "runAfter"):
        compare("For_Each_Alarm_AlertBacked " + field,
                action_field(root_import, "For_Each_Alarm_AlertBacked", field),
                action_field(mod_import, "For_Each_Alarm_AlertBacked", field))
    compare("Verify_Import_Complete", action_field(root_import, "Verify_Import_Complete", "expression"),
            action_field(mod_import, "Verify_Import_Complete", "expression"))
    compare("Fail_Incomplete_Import", action_field(root_import, "Fail_Incomplete_Import", "inputs"),
            action_field(mod_import, "Fail_Incomplete_Import", "inputs"))
    compare("Check_Needs_Entity_Lookup", action_field(root_sync, "Check_Needs_Entity_Lookup", "expression"),
            action_field(mod_sync, "Check_Needs_Entity_Lookup", "expression"))
    for name in ("Get_Incident_Entities", "Filter_Alarm_Url_Entities", "Alarm_ID_From_Entities", "Resolve_Alarm_ID"):
        compare(name, action_field(root_sync, name, "inputs"), action_field(mod_sync, name, "inputs"))
    compare("Check_If_Closed_And_Not_Synced runAfter", run_after(root_sync, "Check_If_Closed_And_Not_Synced"),
            run_after(mod_sync, "Check_If_Closed_And_Not_Synced"))

    # The analytics rule and its automation rule live in a nested template in both copies.
    def nested_rule(template):
        for resource in template.get("resources", []):
            if resource.get("name") == "deploy-alert-backed-rule":
                return json.dumps(resource["properties"]["template"], sort_keys=True)
        return None
    compare("deploy-alert-backed-rule template", nested_rule(root), nested_rule(load(IMPORT)))

    # The audit row's own fields: standalone once logged the alarm id into IncidentId,
    # losing the Sentinel incident name the shipped KQL projects.
    compare("Log_Audit_Event body", request_body(root_import, "Log_Audit_Event"),
            request_body(mod_import, "Log_Audit_Event"))

    # Redaction: every data collection rule in root and the standalone infrastructure
    # playbooks must keep the pack() allow-list. Workbook has no DCR and is not part
    # of this sweep.
    for label, path in (("root", ROOT), ("alarms infrastructure", ALARMS_INFRA), ("audit infrastructure", AUDIT_INFRA)):
        for kql in transforms(load(path)):
            if not kql or "pack(" not in kql:
                failures.append(f"transformKql in {label}: missing the pack() allow-list (value: {str(kql)[:60]})")

    # An existing workspace must never be rewritten by the deployment. A workspace resource
    # in a template is a create-or-update, so an ungated one PUTs sku=PerGB2018 over the
    # target workspace and silently drops a commitment tier off a customer's bill. The gate
    # has to be an explicit opt-in parameter: resource-group equality alone does not catch
    # the common case of deploying into the resource group that already contains the
    # workspace. See EXP-AZURE-0160.
    root_variables = root.get("variables", {})

    def expand_variables(expression):
        """Inline one level of variables('x') so the check reads through an indirection."""
        def swap(match):
            value = root_variables.get(match.group(1))
            return value if isinstance(value, str) else match.group(0)
        return re.sub(r"variables\('([^']+)'\)", swap, expression)

    workspaces = [r for r in root.get("resources", [])
                  if r.get("type") == "Microsoft.OperationalInsights/workspaces"]
    if not workspaces:
        failures.append("azuredeploy.json: no workspace resource found - this check has gone blind")
    for resource in workspaces:
        condition = resource.get("condition", "")
        if "DeployNewWorkspace" not in expand_variables(condition):
            failures.append(
                "azuredeploy.json: the workspace resource is not gated on DeployNewWorkspace "
                f"(condition: {condition or 'none'}) - it would overwrite an existing workspace's sku"
            )
    # The workspace resource must state no workspace-level settings. A template overwrites
    # exactly the fields it states, so an empty properties block is what makes a mistaken
    # DeployNewWorkspace=true harmless instead of a pricing-tier rewrite. sku is the field
    # that caused the incident; the others are here because they carry the same blast radius.
    for resource in workspaces:
        stated = set((resource.get("properties") or {}).keys())
        dangerous = stated & {"sku", "retentionInDays", "workspaceCapping",
                              "publicNetworkAccessForIngestion", "publicNetworkAccessForQuery"}
        if dangerous:
            failures.append(
                "azuredeploy.json: the workspace resource states "
                f"{sorted(dangerous)} - a deployment would write these over an existing workspace"
            )

    if root.get("parameters", {}).get("DeployNewWorkspace", {}).get("defaultValue") is not False:
        failures.append(
            "azuredeploy.json: DeployNewWorkspace must default to false, so the one-click deployment "
            "never creates or rewrites a workspace unless the operator asks for it"
        )

    # DeployNewWorkspace=false against a WorkspaceName that does not exist is the default
    # one-click path with one typo in it, and until task_azure_0057 it half-installed: ARM
    # counts a condition:false resource as a satisfied dependency, so depending on the
    # workspace resource stopped nothing. The storage account, the data collection
    # endpoint, the API connection, the workbook and the Sync playbook were all created
    # and only then did the deployment fail. A nested deployment that resolves the
    # existing workspace has to run first, and everything else has to wait on it.
    GUARD = "precheck-workspace-exists"
    resources = root.get("resources", [])
    guard = [r for r in resources if r.get("name") == GUARD]
    if not guard:
        failures.append(
            f"azuredeploy.json: no {GUARD} nested deployment - a wrong WorkspaceName with "
            "DeployNewWorkspace=false would create resources before failing"
        )
    else:
        condition = expand_variables(guard[0].get("condition", ""))
        if "DeployNewWorkspace" not in condition:
            failures.append(
                f"azuredeploy.json: {GUARD} is not gated on DeployNewWorkspace "
                f"(condition: {guard[0].get('condition') or 'none'}) - it would look for a "
                "workspace this deployment is about to create"
            )
        inner = (guard[0].get("properties", {}).get("template", {})
                          .get("outputs") or {})
        if "reference(" not in json.dumps(inner):
            failures.append(
                f"azuredeploy.json: {GUARD} does not reference the workspace, so it "
                "succeeds whether the workspace exists or not"
            )
        if (guard[0].get("properties", {}).get("expressionEvaluationOptions", {})
                    .get("scope") != "inner"):
            failures.append(
                f"azuredeploy.json: {GUARD} does not use inner expression evaluation, so "
                "its reference() resolves in the parent scope and never fails"
            )
        guard_id = f"[resourceId('Microsoft.Resources/deployments', '{GUARD}')]"
        unguarded = [
            r.get("name") for r in resources
            if r.get("name") != GUARD
            and r.get("type") != "Microsoft.OperationalInsights/workspaces"
            and guard_id not in (r.get("dependsOn") or [])
        ]
        if unguarded:
            failures.append(
                f"azuredeploy.json: {len(unguarded)} resource(s) do not wait for {GUARD} "
                f"and would be created before the workspace check fails: {unguarded[:4]}"
            )

    # Cross-RG has two more ways to look green and be dead, both of them the same ARM
    # semantics as above. The SecurityInsights solution and onboardingStates/default are
    # gated on not(isExternalWorkspace), so nothing onboards an external workspace and the
    # deployment succeeds against one with no Microsoft Sentinel on it (measured). And the
    # alert-backed analytics rule is gated on IncidentMode alone while the alarm table it
    # queries is gated on not(isExternalWorkspace), so the rule would be created against a
    # table that does not exist. precheck-external-workspace asserts both.
    GUARD2 = "precheck-external-workspace"
    guard2 = [r for r in resources if r.get("name") == GUARD2]
    if not guard2:
        failures.append(
            f"azuredeploy.json: no {GUARD2} nested deployment - a cross-RG deployment would "
            "succeed against a workspace with no Microsoft Sentinel, and would accept "
            "AlertBacked without the alarm table it needs"
        )
    else:
        props = guard2[0].get("properties", {})
        inner = props.get("template", {})
        condition = expand_variables(guard2[0].get("condition", ""))
        if "WorkspaceResourceGroup" not in condition:
            failures.append(
                f"azuredeploy.json: {GUARD2} is not gated on the workspace resource group "
                f"(condition: {guard2[0].get('condition') or 'none'}) - it would run in the "
                "same-RG case, where this template does the onboarding itself"
            )
        if props.get("expressionEvaluationOptions", {}).get("scope") != "inner":
            failures.append(
                f"azuredeploy.json: {GUARD2} does not use inner expression evaluation, so "
                "neither its reference() nor its allowedValues is enforced"
            )
        if "onboardingStates" not in json.dumps(inner.get("outputs") or {}):
            failures.append(
                f"azuredeploy.json: {GUARD2} does not reference onboardingStates, so a "
                "cross-RG deployment onto a workspace without Microsoft Sentinel still succeeds"
            )
        # 'Full' references on this proxy resource have no .name -- asking for it fails the
        # guard for every legitimate cross-RG customer while the reject branches stay green.
        if ".name]" in json.dumps(inner.get("outputs") or {}):
            failures.append(
                f"azuredeploy.json: {GUARD2} reads .name off a Full reference, which does not "
                "exist on onboardingStates - the guard would fail even when Sentinel IS onboarded"
            )
        allowed = ((inner.get("parameters") or {}).get("IncidentMode") or {}).get("allowedValues")
        if allowed != ["Direct"]:
            failures.append(
                f"azuredeploy.json: {GUARD2} does not restrict IncidentMode to ['Direct'] "
                f"(found {allowed}) - AlertBacked cross-RG would deploy a rule with no table"
            )
        guard2_id = f"[resourceId('Microsoft.Resources/deployments', '{GUARD2}')]"
        unguarded2 = [
            r.get("name") for r in resources
            if r.get("name") not in (GUARD, GUARD2)
            and r.get("type") != "Microsoft.OperationalInsights/workspaces"
            and guard2_id not in (r.get("dependsOn") or [])
        ]
        if unguarded2:
            failures.append(
                f"azuredeploy.json: {len(unguarded2)} resource(s) do not wait for {GUARD2}: "
                f"{unguarded2[:4]}"
            )

    # No template may hardcode the Azure public cloud ARM host. environment().resourceManager
    # is what lets the same template deploy into a sovereign cloud, and a single leftover
    # literal is enough to break it silently: the call only 404s at run time, never at
    # validate time. The $schema URLs are a different host and stay as they are.
    for path in ALL_TEMPLATES:
        rel = os.path.relpath(path, REPO)
        for lineno, line in enumerate(open(path).read().split("\n"), 1):
            if "https://management.azure.com" not in line:
                continue
            if "schema.management.azure.com" in line:
                continue
            failures.append(f"{rel}:{lineno}: hardcoded ARM host - use environment().resourceManager")

    # Same rule for the storage endpoint the checkpoint is read from and written to.
    # environment().suffixes.storage carries the right suffix per cloud; a literal
    # core.windows.net sends a sovereign-cloud deployment to a host that does not exist.
    for path in ALL_TEMPLATES:
        rel = os.path.relpath(path, REPO)
        for lineno, line in enumerate(open(path).read().split("\n"), 1):
            if "core.windows.net" in line:
                failures.append(f"{rel}:{lineno}: hardcoded storage host - use environment().suffixes.storage")

    # The variable that resolves the ARM host has to be identical in all three templates
    # that build ARM URLs, or one copy silently keeps talking to the wrong cloud.
    base_expressions = {}
    for path in (ROOT, IMPORT, SYNC):
        base_expressions[os.path.relpath(path, REPO)] = load(path).get("variables", {}).get("managementBaseUrl")
    if None in base_expressions.values() or len(set(base_expressions.values())) != 1:
        failures.append("managementBaseUrl is missing or differs between templates: "
                        + json.dumps(base_expressions, indent=2))

    # A workflow that builds an ARM URL at run time reads the host from a workflow
    # parameter. An undeclared or unsupplied parameter makes the whole definition invalid,
    # and a declared-but-unused one means the URLs went back to a literal.
    for path in (ROOT, IMPORT, SYNC):
        rel = os.path.relpath(path, REPO)
        for resource in load(path).get("resources", []):
            if resource.get("type") != "Microsoft.Logic/workflows":
                continue
            definition = resource["properties"]["definition"]
            used = "ManagementBaseUrl" in json.dumps(definition.get("actions", {}))
            declared = "ManagementBaseUrl" in (definition.get("parameters") or {})
            supplied = "ManagementBaseUrl" in (resource["properties"].get("parameters") or {})
            if used and not (declared and supplied):
                failures.append(f"{rel}: a workflow uses ManagementBaseUrl without declaring it "
                                f"(declared={declared}, supplied={supplied})")
            if declared and not used:
                failures.append(f"{rel}: ManagementBaseUrl is declared but no action uses it")

    # The checkpoint variables must be identical in the two templates that build the table
    # URL, for the same reason managementBaseUrl must be: one copy pointing at a different
    # account or table means the two deployments keep separate, silently diverging windows.
    for name in ("checkpointStorageAccountName", "checkpointTableName", "checkpointTableUrl"):
        values = {os.path.relpath(path, REPO): load(path).get("variables", {}).get(name)
                  for path in (ROOT, IMPORT)}
        if None in values.values() or len(set(values.values())) != 1:
            failures.append(f"{name} is missing or differs between templates: " + json.dumps(values, indent=2))

    # And the workflow parameter that carries it has to be declared, supplied and used
    # together - the same three-way check the ARM host parameter gets.
    for path in (ROOT, IMPORT, SYNC):
        rel = os.path.relpath(path, REPO)
        for resource in load(path).get("resources", []):
            if resource.get("type") != "Microsoft.Logic/workflows":
                continue
            definition = resource["properties"]["definition"]
            used = "CheckpointTableUrl" in json.dumps(definition.get("actions", {}))
            declared = "CheckpointTableUrl" in (definition.get("parameters") or {})
            supplied = "CheckpointTableUrl" in (resource["properties"].get("parameters") or {})
            if used and not (declared and supplied):
                failures.append(f"{rel}: a workflow uses CheckpointTableUrl without declaring it "
                                f"(declared={declared}, supplied={supplied})")
            if declared and not used:
                failures.append(f"{rel}: CheckpointTableUrl is declared but no action uses it")

    # Bounded retries and loops, so a failing API call cannot stall the integration.
    # Swept across every template in the repo (not just root/import/sync) -- this is a
    # cheap regression net.
    for path in ALL_TEMPLATES:
        raw = open(path).read()
        if '"PT1H"' in raw:
            failures.append(f"{os.path.relpath(path, REPO)}: still contains a PT1H retry or loop timeout")

    # A loop must keep advancing even when one record in it fails, and no request
    # body may ship result(). Both classes broke the import live on 2026-08-18.
    for path in ALL_TEMPLATES:
        template = load(path)
        rel = os.path.relpath(path, REPO)
        for loop_path, loop in until_loops(template):
            for stall in stalled_progress(loop):
                failures.append(f"{rel}: {loop_path} cannot advance past a failed record ({stall})")
        for offender in unbounded_result_payloads(template):
            failures.append(f"{rel}: {offender} puts result() in a request body")

    if failures:
        print("TEMPLATE DRIFT DETECTED\n")
        for item in failures:
            print("  - " + item)
        print(f"\n{len(failures)} problem(s). Update the standalone templates under Playbooks/ to match azuredeploy.json.")
        return 1

    print("No drift: standalone templates match azuredeploy.json on all checked invariants.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
