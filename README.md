# SOCRadar Alarms for Microsoft Sentinel

Bidirectional integration between SOCRadar and Microsoft Sentinel. Alarms come in as incidents, closed incidents sync back.

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Forcunsami%2FSOCRadar-Azure-Incidents%2Fmaster%2Fazuredeploy.json)

## Architecture

### Alarm Import

Pulls alarms from SOCRadar and opens Sentinel incidents. Deduplicates by title, tags with the alarm type/subtype. OPEN only by default.

```mermaid
flowchart LR
    A["SOCRadar Platform<br/>Alarms API"] --> B["SOCRadar-Alarm-Import<br/>Logic App"]
    B --> C["Microsoft Sentinel<br/>Incidents"]
```

### Alarm Sync

When you close a SOCRadar-tagged incident in Sentinel, the classification maps back to a SOCRadar status and the alarm is updated.

```mermaid
flowchart LR
    A["Microsoft Sentinel<br/>Closed Incidents"] --> B["SOCRadar-Alarm-Sync<br/>Logic App"]
    B --> C["SOCRadar Platform<br/>status + severity update"]
```

### Analytics

Alarms and audit events are also written to custom Log Analytics tables. Hunting queries, analytic rules, and the workbook read from them. All three (audit, alarms table, workbook) are toggleable at deploy time.

### IOC Enrichment (optional add-on)

Deployed separately from the main template. When an incident is created, this playbook looks up each related entity (IP, domain, URL, file hash) in **SOCRadar IOC Enrichment** and posts a comment with the risk score, signal strength, categorization, and threat actors.

```mermaid
flowchart LR
    A["Microsoft Sentinel<br/>Incident"] --> B["SOCRadar-IOC-Enrichment<br/>Logic App"]
    B --> C["SOCRadar IOC Enrichment<br/>indicator_details API"]
    C --> D["Incident Comment<br/>risk score + context"]
```

Deploy `Playbooks/SOCRadar-IOC-Enrichment/azuredeploy.json` on its own:

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Forcunsami%2FSOCRadar-Azure-Incidents%2Fmaster%2FPlaybooks%2FSOCRadar-IOC-Enrichment%2Fazuredeploy.json)

Notes:

- `SocradarApiKey` is your normal company key (same one used by Import/Sync), used here to fetch the original alarm's related entities. IOC enrichment itself needs a **separate** key with the **IOC Enrichment** entitlement (Standard Licensed APIs / advanced tier -- contact integration@socradar.io). Set `SocradarIocApiKey` to that key; leave it empty to reuse `SocradarApiKey` for enrichment too. If the key used for enrichment lacks the entitlement, calls return HTTP 402 and nothing is enriched; the playbook then posts a single summary comment saying so.
- `MaxIndicators` (default `20`) caps how many indicators one incident enriches. Each enrichment spends one SOCRadar API credit, and an alarm incident can carry 100 entities, so raise it only if your credit budget allows.
- `RiskScoreThreshold` (default `0`) -- only comments when the score is at or above this value. Benign whitelisted indicators scoring 0 are skipped.
- Indicators that are still being looked up (HTTP 202) or that failed are collected into one summary comment instead of one comment each.
- Microsoft Sentinel needs permission on this resource group before it can run the playbook. Either pass `SentinelServicePrincipalObjectId` at deploy time, or afterwards open **Microsoft Sentinel > Settings > Playbook permissions > Configure permissions** and add this resource group. Without it, running the playbook fails with `Missing required permissions for Microsoft Sentinel on the playbook resource`.

  ```bash
  az ad sp list --filter "appId eq '98785600-1bb7-4fb9-b9fa-19afe2c8a360'" --query "[0].id" -o tsv
  ```

- After deployment, create a Microsoft Sentinel **automation rule** (when an incident is created -> run this playbook) in the portal.
- Microsoft Sentinel **Responder** role is sufficient for the playbook itself.

## Prerequisites

- Microsoft Sentinel workspace
- SOCRadar API key and Company ID

## Parameters

### Required

| Parameter | Description |
|-----------|-------------|
| `WorkspaceName` | Sentinel workspace name (not the GUID) |
| `WorkspaceLocation` | Workspace region (e.g., `northeurope`) |
| `SocradarApiKey` | Your SOCRadar API key |
| `CompanyId` | Your SOCRadar company ID |

### Optional

| Parameter | Default | Description |
|-----------|---------|-------------|
| `WorkspaceResourceGroup` | deployment RG | Set if workspace is in a different RG |
| `SentinelRoleLevel` | `Responder` | `Responder` (least-privilege) or `Contributor` |
| `PollingIntervalMinutes` | `5` | How often to check for alarms (1-60) |
| `InitialLookbackMinutes` | `600` | First-run lookback window (10 hours) |
| `ImportAllStatuses` | `false` | `true` imports RESOLVED / FALSE_POSITIVE / MITIGATED too |
| `EnableAuditLogging` | `true` | Writes audit events to `SOCRadarAuditLog_CL` |
| `EnableAlarmsTable` | `true` | Stores full alarm JSON in `SOCRadar_Alarms_CL` |
| `EnableWorkbook` | `true` | Deploys the SOCRadar Dashboard workbook |
| `TableRetentionDays` | `365` | Retention for custom tables (30-730) |

## What Gets Deployed

- **SOCRadar-Alarm-Import** Logic App -- imports alarms as incidents
- **SOCRadar-Alarm-Sync** Logic App -- syncs closed incidents back
- **SOCRadar_Alarms_CL** custom table (optional)
- **SOCRadarAuditLog_CL** audit table (optional)
- **SOCRadar Dashboard** workbook (optional)
- Data Collection Endpoint and Rules for custom tables

## Role Selection

Logic Apps run with Managed Identity:

- **Responder** (default) -- enough for create / update / close / classify.
- **Contributor** -- only if you rely on automation rules that need elevated access.

## Cross-Region / Cross-RG

- Different region -> set `WorkspaceLocation`.
- Different resource group -> set `WorkspaceResourceGroup`. Custom tables and workbook deploy into the workspace RG.

## Post-Deployment

Logic Apps start 3 minutes after deployment, so role assignments have time to propagate.

## Standalone vs. Microsoft Sentinel Content Hub

This repository is the standalone one-click deployment. It provisions the infrastructure (Data Collection Endpoint, Data Collection Rules, and custom tables) as separate resources alongside the Logic Apps.

The same integration is also available as a Microsoft Sentinel Solution via **Content Hub -> SOCRadar**. In that distribution, the infrastructure is provisioned inside the Alarm Import playbook template so it shows up under **Automation -> Playbook templates**. Both paths end up with the same workspace state; choose whichever fits your installation workflow.

## Support

- **Public Documentation:** [One-Click Deployment Guide](https://github.com/Radargoger/azure-one-click-documentations/blob/main/azureincidents.md)
- **Detailed Documentation (SOCRadar customers):** [Microsoft Azure Sentinel Integration (Bi-Directional)](https://help.socradar.io/hc/en-us/articles/41316851769745-Microsoft-Azure-Sentinel-Integration-Bi-Directional)
- **Support email:** integration@socradar.io
