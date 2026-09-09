# SOCRadar Alarms for Microsoft Sentinel

Bidirectional integration between SOCRadar and Microsoft Sentinel. Alarms come in as incidents, closed incidents sync back.

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Forcunsami%2FSOCRadar-Azure-Incidents%2Fmaster%2Fazuredeploy.json)

## Architecture

### Alarm Import

Pulls alarms from SOCRadar and opens Microsoft Sentinel incidents. Each incident is titled
`[SOCRadar] #<alarm id> - <title>` and labelled with the alarm id, type, subtype and SOCRadar
severity. OPEN alarms only by default. See [Import window and
de-duplication](#import-window-and-de-duplication) for how it picks its window and skips alarms
it has already imported.

```mermaid
flowchart LR
    A["SOCRadar Platform<br/>Alarms API"] --> B["SOCRadar-Alarm-Import<br/>Logic App"]
    B --> C["Microsoft Sentinel<br/>Incidents"]
```

### Alarm Sync

When you close a SOCRadar-labelled incident in Microsoft Sentinel, the classification maps back to a SOCRadar status and the alarm is updated.

```mermaid
flowchart LR
    A["Microsoft Sentinel<br/>Closed Incidents"] --> B["SOCRadar-Alarm-Sync<br/>Logic App"]
    B --> C["SOCRadar Platform<br/>status update"]
```

### Analytics

Alarms and audit events are also written to custom Log Analytics tables. Hunting queries, analytic rules, and the workbook read from them. All three (audit, alarms table, workbook) are toggleable at deploy time.

## Prerequisites

- Microsoft Sentinel workspace -- `WorkspaceName` is either an existing workspace or a new
  name; a new name is created as part of this deployment (`DeployNewWorkspace`, default `true`)
- SOCRadar API key and Company ID

## Parameters

### Required

| Parameter | Description |
|-----------|-------------|
| `WorkspaceName` | Microsoft Sentinel workspace name (not the GUID) |
| `WorkspaceLocation` | Workspace region (e.g., `northeurope`) |
| `SocradarApiKey` | Your SOCRadar API key |
| `CompanyId` | Your SOCRadar company ID |

A wrong `WorkspaceName` with `DeployNewWorkspace=false` now fails before anything is created.
The deployment resolves the workspace in a `precheck-workspace-exists` step that every other
resource waits on, so the resource group is left empty and the only failed operation is that
one step. Measured on a fresh resource group: `0` resources afterwards.

This used to half-install. Depending on the workspace resource was not enough, because ARM
counts a resource whose `condition` is false as a satisfied dependency -- so the checkpoint
storage account, the Data Collection Endpoint, the workbook, the Microsoft Sentinel API
connection and an **enabled** SOCRadar-Alarm-Sync Logic App were all created, and only then did
the deployment fail. If you are looking at a resource group in that state from an earlier
attempt, redeploying over it with the correct name reconciles it; the Logic App in it is
billable until then, so disable it or delete the resource group.

With `DeployNewWorkspace` at its default `true` a typo does not fail: it creates a second,
empty workspace under the misspelled name. The pre-check is skipped in that mode, because the
workspace may not exist yet. Set it `false` when the workspace must already exist.

### Redeploy to fix a failed deployment -- do not delete the Logic Apps first

Redeploying over the same resource group is safe and is the way to fix a failed or partial
deployment. Deleting the Logic Apps and starting again is **not**, and this is the one recovery
step that makes things worse.

The role assignments are named after the workspace and the playbook, not after the identity
they grant. Deleting a Logic App leaves its assignment behind at workspace scope with a
principal that no longer exists. The next deployment creates a new Logic App with a new
identity, computes the same assignment name, and Azure refuses to move an existing assignment
to a different principal:

```
RoleAssignmentUpdateNotPermitted
Tenant ID, application ID, principal ID, and scope are not allowed to be updated.
```

To recover, delete the orphaned assignments and redeploy. An orphan is the one with no
`principalName` -- its principal is gone:

```bash
WS=$(az monitor log-analytics workspace show -g <workspace-rg> -n <workspace> --query id -o tsv)
az role assignment list --scope "$WS" \
  --query "[?principalName==null].{name:name, role:roleDefinitionName}" -o table
az role assignment delete --ids "$WS/providers/Microsoft.Authorization/roleAssignments/<name>"
```

Measured: after that, the same deployment succeeds in 34 seconds and both Logic Apps come back.

The pre-check cannot catch this -- ARM can assert that a resource exists, not that it is
absent. Renaming the assignments is not an option either: Azure rejects a second assignment for
the same identity, role and scope with `RoleAssignmentExists`, so a new naming scheme would
break redeployment for every existing install. Both measured.

The same collision is why two installs cannot share one workspace. For several SOCRadar
companies in one workspace, use the MSSP edition, which is built for it.

### Cross-RG: Microsoft Sentinel must already be onboarded, and AlertBacked is not available

When `WorkspaceResourceGroup` points somewhere else, this template does not onboard the
workspace -- both the Microsoft Sentinel solution and its onboarding state are only created in
the deployment resource group. A `precheck-external-workspace` step therefore reads the
workspace's onboarding state and stops the deployment if Microsoft Sentinel is not there:

```
Microsoft Sentinel was not found on the workspace '<name>'
```

This used to succeed. The deployment went green and the integration was dead, because a
workspace can carry the Microsoft Sentinel solution and still have no onboarding state.

The same step rejects `IncidentMode=AlertBacked` cross-RG, during template validation, before
anything is created:

```
The provided value for the template parameter 'IncidentMode' is not valid.
The value 'AlertBacked' is not part of the allowed value(s): 'Direct'.
```

Alert-backed mode needs `SOCRadar_Alarms_CL` and its data collection rule, and this template
only creates those in its own resource group -- but the analytics rule that queries the table
is gated on `IncidentMode` alone, so it would have been created against a table that does not
exist. Deploy into the workspace's own resource group to use alert-backed mode.

### Optional

| Parameter | Default | Description |
|-----------|---------|-------------|
| `WorkspaceResourceGroup` | deployment RG | Set if workspace is in a different RG. Changes what gets deployed -- see [Cross-Region / Cross-RG](#cross-region--cross-rg) |
| `DeployNewWorkspace` | `true` | Create `WorkspaceName` when it does not exist yet. An existing workspace of that name is left as it is: the workspace resource states no settings, and a live check found tags, pricing tier, retention, daily cap and feature flags unchanged after redeploying. `false` requires the workspace to exist and fails on a misspelled name before anything is created. Ignored when `WorkspaceResourceGroup` is not the deployment RG. An existing workspace in a region other than `WorkspaceLocation` fails with `InvalidResourceLocation` and nothing is created -- set `WorkspaceLocation` to its region. |
| `SentinelRoleLevel` | `Responder` | `Responder` (least-privilege) or `Contributor` |
| `PollingIntervalMinutes` | `5` | How often to check for alarms (1-60). Also sets the floor of the import window and the Sync lookback |
| `InitialLookbackMinutes` | `600` | Lookback window when there is no checkpoint yet (10 hours) |
| `ImportAllStatuses` | `false` | `true` imports RESOLVED / FALSE_POSITIVE / MITIGATED too, as already-closed incidents -- see [Importing closed alarms](#importing-closed-alarms) |
| `IncidentMode` | `Direct` | `Direct` creates the incidents from the import Logic App. `AlertBacked` writes the alarms to `SOCRadar_Alarms_CL` and a scheduled analytics rule raises one alert and one incident per alarm, which is what makes them show up in the Microsoft Defender portal -- see [Incident mode](#incident-mode) |
| `SyncSeverity` | `true` | Push the Microsoft Sentinel severity back to SOCRadar on close. Raise-only, a severity is never lowered -- see [Severity write-back](#severity-write-back) |
| `EnableIoCEnrichment` | `true` | Attach IP/domain/URL indicators from the alarm to the incident as entities (see [IoC Entity Enrichment](#ioc-entity-enrichment)) |
| `EnableAuditLogging` | `true` | Writes audit events to `SOCRadarAuditLog_CL` |
| `EnableAlarmsTable` | `true` | Stores alarm fields in `SOCRadar_Alarms_CL`. The workbook and four of the five hunting queries need it. Forced on by `IncidentMode=AlertBacked` |
| `EnableWorkbook` | `true` | Deploys the SOCRadar Dashboard workbook. Needs `EnableAlarmsTable=true` -- with the table off, the workbook is skipped even when this is `true` |
| `TableRetentionDays` | `365` | Retention for custom tables (30-730) |

## Existing installations

Deployments made before `DeployNewWorkspace` existed stated a pricing tier on the workspace
resource, and a template overwrites every field it states. If the target workspace was on a
**commitment tier**, that deployment reset it to `PerGB2018` (pay-as-you-go).

Check the current tier:

```bash
az monitor log-analytics workspace show -g <resource-group> -n <workspace> \
  --query "{sku:sku.name, lastSkuUpdate:sku.lastSkuUpdate}" -o json
```

If `lastSkuUpdate` lines up with when you first deployed this integration and the tier isn't
the one you picked, reset your commitment tier from **Log Analytics workspaces > Usage and
estimated costs > Pricing tier**. The current template states no workspace-level settings at
all, so redeploying or upgrading an existing install -- even with `DeployNewWorkspace=true` set
by mistake -- cannot change its pricing tier, retention or daily cap; a mutation test against a
live workspace (non-default 90-day retention, `DeployNewWorkspace=true`) confirmed both the
retention and `sku.lastSkuUpdate` came back untouched after redeploying.

Upgrading also resets the import window once. The checkpoint lives in a storage account named
after the resource group and workspace, so an upgrade in place reuses the same account and keeps
the checkpoint; a deployment into a *different* resource group starts with an empty one and the
first run falls back to `InitialLookbackMinutes`. Either way the de-duplication snapshot stops
that from re-importing anything.

Upgrading from v1.0.0 also turns the severity write-back back on: `SyncSeverity` now defaults
to `true`, which restores v1.0.0's always-write behaviour with one difference, the raise-only
guard, so a SOCRadar CRITICAL alarm is never lowered to High. Pass `SyncSeverity=false` on the
upgrade if you had turned it off.

## What Gets Deployed

- **SOCRadar-Alarm-Import** Logic App -- imports alarms as incidents
- **SOCRadar-Alarm-Sync** Logic App -- syncs closed incidents back
- **Checkpoint storage account** -- one Standard_LRS account with a single `ImportState` table
  holding one row per company, so the import knows where it left off. Shared-key access is
  disabled; the Logic App reads and writes it with its own managed identity
- **SOCRadar_Alarms_CL** custom table (optional)
- **SOCRadarAuditLog_CL** audit table (optional)
- **SOCRadar Dashboard** workbook (optional, needs the alarms table)
- **Five hunting queries** under **Microsoft Sentinel > Hunting** (see [Hunting Queries](#hunting-queries))
- Data Collection Endpoint and Rules for custom tables
- **Workspace** -- when `DeployNewWorkspace=true` (default) and no workspace of that name exists in the deployment RG, with the subscription default tier; an existing one is left untouched
- **Microsoft Sentinel onboarding** -- applied whenever the workspace is in the deployment RG, new or existing
- Role assignments giving each Logic App identity least privilege: Log Analytics Reader,
  Monitoring Metrics Publisher on each DCR, Storage Table Data Contributor on the checkpoint
  account, and the Microsoft Sentinel role from `SentinelRoleLevel`
  (the import identity is raised to Contributor only while `EnableIoCEnrichment=true`)

One deployment installs all of the above. The templates under `Playbooks/` exist for
environments that deploy the pieces separately -- see [below](#deploying-playbooks-separately-not-recommended).

## Incident Labels

Every imported incident carries these labels. Sync and the hunting queries read them, so they
are a contract, not decoration.

| Label | Example | Purpose |
|---|---|---|
| `SOCRadar` | `SOCRadar` | Marks the incident as ours. Sync only looks at incidents that have it |
| `SOCRadar-Alarm-<id>` | `SOCRadar-Alarm-104658646` | The machine-readable alarm id Sync writes back against |
| alarm main type | `Domain` | From `alarm_type_details.alarm_main_type` |
| alarm sub type | `Impersonating Domain` | From `alarm_type_details.alarm_sub_type`, when the alarm has one |
| `SOCRadar-Severity-<LEVEL>` | `SOCRadar-Severity-CRITICAL` | The SOCRadar severity, which is what stops [Severity write-back](#severity-write-back) from lowering it |

Incidents imported as already closed carry a sixth label, `Synced` -- see
[Importing closed alarms](#importing-closed-alarms).

In `AlertBacked` mode the incidents carry only `SOCRadar`; an automation rule cannot set per-alarm
labels. The alarm id is on the incident's URL entity instead -- see [Incident mode](#incident-mode).

Sync reads the alarm id from `SOCRadar-Alarm-<id>`, falls back to parsing it out of the
incident title, and last to the incident's URL entity (`.../alarm/<id>`), so incidents created
before these labels existed, and alert-backed incidents, still sync. The obvious field
for this, `providerIncidentId`, cannot be used: Azure overwrites both it and `providerName` on
any incident created through the API, silently and without an error.

## Import window and de-duplication

**The window** decides how far back to ask SOCRadar for alarms. It comes from a checkpoint row
in the deployed storage table (`PartitionKey` = your company id, `RowKey` = `import`), stamped
with the time the run *started*:

- No row yet -- first run, or a deployment into a new resource group -- falls back to
  `InitialLookbackMinutes` (600).
- Otherwise the gap since the last successful run, plus 15 minutes of overlap, with a floor of
  `max(PollingIntervalMinutes x 6, 60)` minutes and a ceiling of 7 days.
- The row is written only after the run has read every page. A run that dies halfway leaves the
  window where it was, so nothing is skipped.
- On a fresh deployment the first write can fail while the role assignment propagates. That is
  recorded in the run history and is not fatal: the window stays on the fallback and the next
  run writes the row.
- Cost is negligible -- a handful of rows a day in a Standard_LRS table.

**De-duplication** decides whether an alarm already has an incident. Before importing, the run
lists every `[SOCRadar]`-titled incident in the workspace and skips any alarm whose id is
already there, which is what makes a widened window harmless.

Earlier versions derived the window from the newest existing incident's title. That coupled the
window to the incident list, so a workspace whose incidents had been cleaned up would re-import
from scratch.

## Incident mode

`IncidentMode` decides who creates the incident.

**`Direct`** (default) is what the sections above describe: the import Logic App creates one
incident per alarm through the Microsoft Sentinel API. Those incidents never appear in the
Microsoft Defender portal's unified queue, which only lists incidents backed by an alert.

**`AlertBacked`** makes the import write each alarm to `SOCRadar_Alarms_CL` and nothing else. A
scheduled analytics rule (`SOCRadar alarm`, every 5 minutes, deployed with this mode) raises one
alert per row, and Microsoft Sentinel -- or Microsoft Defender XDR, when the workspace is
onboarded to it -- creates the incident. An automation rule adds the `SOCRadar` label so Sync
finds them.

What is different in `AlertBacked`:

- The alarms table is deployed whatever `EnableAlarmsTable` says, and the workspace has to be in
  the deployment resource group: the table is never created cross-RG and the rule fails to
  deploy without it.
- De-duplication is an `alarm-<id>` row per ingested alarm in the checkpoint table, not the
  incident list. The rows stay (one per alarm ever ingested) and cost next to nothing.
- The import writes at most `48 / (10 / PollingIntervalMinutes + 1)` new alarms per run (16 at
  the default 5 minutes) and holds the checkpoint when it hits that cap, so a backlog drains
  over the following runs instead of landing in one rule run. The reason is a documented
  platform limit: a rule run with more than 50 customised values drops every customised title
  and severity for that run (a 58-row run kept them in our test, so read the cap as a guard,
  not as the edge). The rule keeps a 10-minute ingestion window, so the cap keeps a run under
  that. A run that still exceeds the limit gets the rule's default name and Medium severity;
  the alarm id is on the incident's URL entity either way, which is what Sync uses.
- Each alarm is written once and the incident is Microsoft Sentinel's to create. If the platform
  skips a rule run (seen once on a fresh test workspace, for about 25 minutes: alerts written, no
  incidents), those alarms are not re-alerted and never get an incident. `Direct` has no such
  dependency.
- Incident title `[SOCRadar] #<id> - <title>`; severity mapped as in Direct mode (CRITICAL/HIGH ->
  High, MEDIUM -> Medium, everything else -> Low); label `SOCRadar` only. The description is the
  alarm text followed by a `SOCRadar severity: <LEVEL>` line. These incidents carry no
  `SOCRadar-Severity-*` label, so Sync reads the level from that line and severity write-back
  behaves as in Direct mode; editing the line away only switches the write-back off for that
  incident.
- Every alarm row is seen by two consecutive rule runs: the 10-minute window overlaps the
  5-minute interval on purpose, because a late run must not skip rows and a skipped row is never
  retried. The second alert joins the same incident, so an incident normally shows 2 alerts. An
  incident closed inside those 10 minutes comes back once as a new incident; close it again.
- Verified against a workspace that is not connected to Microsoft Defender XDR. On a connected
  workspace Defender names the incident: Sync still finds the alarm through the URL entity, but
  the severity line may be absent, in which case that incident's severity is not written back.
- Closed alarms never become incidents here. With `ImportAllStatuses=true` they still land in
  the table, but the rule only fires on `OPEN`.
- The IoC entity enrichment reaches these incidents on the next import run, through the same
  title match it uses for Direct incidents.
- `PollingIntervalMinutes` below 5 lowers the per-run cap (4 at 1 minute) rather than the
  rule interval, which cannot go below 5.

Switching an existing install from `Direct` to `AlertBacked` re-ingests the current import
window once, and every alarm in it gets a second, rule-created incident; close the old ones.
Switching back does the same in reverse.

## Importing closed alarms

With `ImportAllStatuses=false` (default) only OPEN alarms are imported, as active incidents
through the Microsoft Sentinel connector.

With `ImportAllStatuses=true` every other status is imported too, as an incident that is created
already closed with the classification mapped from the alarm status:

| SOCRadar status | Microsoft Sentinel classification | Classification reason |
|---|---|---|
| `FALSE_POSITIVE` | `FalsePositive` | `InaccurateData` |
| `MITIGATED` | `BenignPositive` | `SuspiciousButExpected` |
| `RESOLVED` | `TruePositive` | `SuspiciousActivity` |
| anything else (e.g. `INVESTIGATING`) | `Undetermined` | none |

These incidents are labelled `Synced` at creation so Sync leaves them alone. Without that label
Sync would treat them as analyst closures and write a status back for a closure SOCRadar itself
reported -- and an alarm that landed on `Undetermined` would come back as `RESOLVED`.

## Severity write-back

Closing an incident always writes the mapped status back to SOCRadar. The **severity** is a
separate write, governed by `SyncSeverity` (default `true`, set `false` to never write it).

The two scales do not line up: Microsoft Sentinel's highest severity is High, SOCRadar's is
CRITICAL. Closing a CRITICAL alarm in Microsoft Sentinel used to push High back and permanently
lower the alarm, with no way to undo it. That is why the write is guarded.

With `SyncSeverity=true` the write can only ever raise a severity:

| SOCRadar alarm | Incident closed as | Written back |
|---|---|---|
| CRITICAL | High / Medium / Low | no -- never lowered |
| HIGH | Medium / Low | no |
| HIGH | High | no -- already equal |
| MEDIUM | High | yes |
| LOW | Medium / High | yes |
| INFO | Low / Medium / High | yes |
| any | Informational | no -- never written back |
| unrecognised severity label | anything | no -- the incident is left alone |

Five levels are recognised: CRITICAL, HIGH, MEDIUM, LOW and INFO. INFO matters more than its
name suggests -- it was 20 of the 35 alarms in the last seven days of the test feed, so an INFO
alarm has to be raisable or the feature does nothing for most of the queue. Any level outside
those five still lands on the incident as a label but carries no rank, so the write-back skips
that incident rather than guessing.

Note that on the way in, an INFO alarm becomes a **Low** incident: the import maps CRITICAL and
HIGH to High, MEDIUM to Medium, and everything else to Low. Microsoft Sentinel's Informational
is not used.

The status mapping in the other direction is fixed:

| Microsoft Sentinel classification | SOCRadar status |
|---|---|
| `FalsePositive` | `9` FALSE_POSITIVE |
| `BenignPositive` | `12` MITIGATED |
| `TruePositive` | `2` RESOLVED |
| `Undetermined` | `2` RESOLVED |

## IoC Entity Enrichment

Microsoft Sentinel's incident API accepts no entities directly, so an incident's **Entities** tab
is fed only by alerts and bookmarks. With `EnableIoCEnrichment` (default `true`), the import
playbook extracts IPv4/domain/URL indicators from the alarm, writes them to a bookmark with
entity mappings, and relates that bookmark to the incident.

- Up to 100 deduplicated indicators per incident; hashes are not extracted; `socradar.com` and
  filename-like values are excluded.
- Bookmark write needs **Microsoft Sentinel Contributor**, which Responder does not include --
  the import playbook's identity is raised to Contributor only while this is `true`.
- Entities can take a few minutes to appear after the incident is created.
- Enrichment failures never block the import -- the incident and audit log are unaffected.

Set `EnableIoCEnrichment=false` to keep the import identity on `SentinelRoleLevel` (Responder).

## Role Selection

Logic Apps run with Managed Identity:

- **Responder** (default) -- enough for create / update / close / classify.
- **Contributor** -- only if you rely on automation rules that need elevated access.

`SentinelRoleLevel` does not apply to the import identity while `EnableIoCEnrichment` is true --
see [IoC Entity Enrichment](#ioc-entity-enrichment).

## Deploying Playbooks Separately (not recommended)

Use the one-click template above for new installs. The templates under `Playbooks/` are kept
for existing separated deployments:

- The standalone Import playbook has the same IoC entity enrichment as the combined template
  (`EnableIoCEnrichment`, default `true`) -- see [IoC Entity Enrichment](#ioc-entity-enrichment).
  Its identity is raised to Contributor the same way. Set `EnableIoCEnrichment=false` if you
  want it to stay on `SentinelRoleLevel`.
- It deploys its own checkpoint storage account. The name is derived from the resource group
  and the workspace, so an import playbook deployed into the same resource group as a combined
  install shares that install's account and checkpoint row; deployed into another resource
  group it keeps its own.
- If you enable the custom tables but leave `AlarmsDcrResourceId` / `AuditDcrResourceId` empty,
  the deployment still succeeds while every ingestion call returns 403 and the tables stay
  silently empty.
- `IncidentMode=AlertBacked` works here too, but the analytics rule it deploys needs
  `SOCRadar_Alarms_CL` to exist already: deploy `SOCRadar-Alarms-Infrastructure` first and pass
  its outputs, as below.

If you still deploy them separately, deploy the infrastructure templates first and pass their
DCR resource ID outputs into the import playbook:

```bash
az deployment group create -g <resource-group> \
  --template-file Playbooks/SOCRadar-Alarms-Infrastructure/azuredeploy.json \
  --parameters WorkspaceName=<workspace> WorkspaceLocation=<region>
# take alarmsDcrId from the deployment output

az deployment group create -g <resource-group> \
  --template-file Playbooks/SOCRadar-Alarm-Import/azuredeploy.json \
  --parameters WorkspaceName=<workspace> SocradarApiKey=<key> CompanyId=<id> \
               EnableAlarmsTable=true DceEndpoint=<dceEndpoint> \
               AlarmsDcrImmutableId=<alarmsDcrImmutableId> AlarmsDcrResourceId=<alarmsDcrId>
```

`tools/check_template_drift.py` compares these standalone templates against `azuredeploy.json`
on every push and PR so they cannot silently fall behind.

## Hunting Queries

Five queries are deployed with the integration and appear under **Microsoft Sentinel >
Hunting**. Nothing to import.

| Query | Reads | Needs |
|---|---|---|
| SOCRadar Alarm Overview | `SOCRadar_Alarms_CL` | `EnableAlarmsTable=true` |
| SOCRadar Critical Alarms | `SOCRadar_Alarms_CL` | `EnableAlarmsTable=true` |
| SOCRadar Alarm Trends | `SOCRadar_Alarms_CL` | `EnableAlarmsTable=true` |
| SOCRadar Incident Correlation | `SecurityIncident` | nothing -- always deployed |
| SOCRadar Audit Analysis | `SOCRadarAuditLog_CL` | `EnableAuditLogging=true` |

The custom tables keep a fixed column list, so a query naming a column outside it would return
nothing forever without failing. `tests/test_hunting_queries.py` checks every column each query
reads against the tables the deployment actually creates.

`socradar-kql-queries.kql` holds these and other queries as plain KQL, for pasting into Logs.

## Analytic Rules

Three scheduled rules ship in `Analytic Rules/` as YAML. They are not created by the
deployment -- import them once the custom tables have data: **Microsoft Sentinel > Analytics >
Import**, then select the files. The first two need `EnableAlarmsTable=true`.

| Rule | Fires when |
|---|---|
| `SOCRadarCriticalAlarmDetection.yaml` | An open alarm arrives with HIGH or CRITICAL severity |
| `SOCRadarAlarmVolumeSpike.yaml` | Hourly alarm count for a type exceeds 3x its 7-day average |
| `SOCRadarUnsyncedClosedIncident.yaml` | A closed SOCRadar incident still has no Synced label after 30 minutes |

## Cross-Region / Cross-RG

- Different region -> set `WorkspaceLocation` to the workspace's own region. A workspace's
  region is independent of its resource group's region, so read it from the workspace
  Overview blade instead of assuming they match -- the parameter defaults to the resource
  group's region, which is wrong whenever they differ. Deploying with the wrong value fails with:

  ```
  LinkedResourceNotFound: Linked Workspace '/subscriptions/.../workspaces/<name>'
  was not found in location '<region>'
  ```

  If the workspace name is correct, the region is the cause: set `WorkspaceLocation` to the
  workspace's region and redeploy -- the message names the resource, not the actual cause.
  (The template cannot read the region off the workspace for you: ARM rejects the
  `reference()` function in a resource's `location` field.)
- Different resource group -> set `WorkspaceResourceGroup`. This deploys **incident import and
  sync only**. Both Logic Apps, the Microsoft Sentinel connection and the checkpoint storage
  account go into the deployment RG, and the role assignments the identities need go into the
  workspace RG. Everything analytics-related is skipped, in both resource groups: the custom
  tables, the Data Collection Endpoint and Rules, the workbook and all five hunting queries.
  `EnableAuditLogging` and `EnableAlarmsTable` are forced off inside the import Logic App to
  match, so nothing tries to ingest into a table that was never created -- you get no silent 403s, and no
  analytics. The Microsoft Sentinel onboarding state is also skipped, so the workspace must
  already be onboarded. `IncidentMode=AlertBacked` is not available cross-RG for the same
  reason: the alarms table it needs is never created there and the deployment fails at the
  analytics rule.
- `DeployNewWorkspace` only works in the deployment resource group -- a workspace cannot be
  created in another RG from this template.

## Post-Deployment

Logic Apps start 3 minutes after deployment, so role assignments have time to propagate.

## Removing the integration

Deleting the resource group removes everything, including the checkpoint storage account. If you
delete resources individually, remember the storage account -- it is the one resource whose name
is derived rather than fixed:

```bash
az storage account list -g <resource-group> --query "[?starts_with(name,'srinc')].name" -o tsv
```

If the workspace is in **another** resource group, deleting the integration resource group leaves
the two role assignments behind at workspace scope with no principal to grant. Azure keeps them,
and a later install from a different resource group then fails with
`RoleAssignmentUpdateNotPermitted` -- the assignment name is derived from the workspace, the
playbook name and the role, so the new identity collides with the orphan. That deployment failure
is not a clean rollback either: the Logic Apps, storage account and API connections it created
before the role step are left enabled. Remove the orphans first, or reuse the original resource
group name:

```bash
az role assignment list --scope <workspace-resource-id> \
  --query "[?principalName==null].{name:name,role:roleDefinitionName}" -o table
az role assignment delete --ids <id>
```

## Standalone vs. Microsoft Sentinel Content Hub

This repository is the standalone one-click deployment. It provisions the infrastructure (Data Collection Endpoint, Data Collection Rules, and custom tables) as separate resources alongside the Logic Apps.

The same integration is also available as a Microsoft Sentinel Solution via **Content Hub -> SOCRadar**. In that distribution, the infrastructure is provisioned inside the Alarm Import playbook template so it shows up under **Automation -> Playbook templates**. Both paths end up with the same workspace state; choose whichever fits your installation workflow.

## Support

- **Public Documentation:** [One-Click Deployment Guide](https://github.com/Radargoger/azure-one-click-documentations/blob/main/azureincidents.md)
- **Detailed Documentation (SOCRadar customers):** [Microsoft Azure Sentinel Integration (Bi-Directional)](https://help.socradar.io/hc/en-us/articles/41316851769745-Microsoft-Azure-Sentinel-Integration-Bi-Directional)
- **Support email:** integration@socradar.io
