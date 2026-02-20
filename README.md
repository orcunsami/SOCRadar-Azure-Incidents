# SOCRadar Alarms for Microsoft Sentinel

Bidirectional integration between SOCRadar XTI Platform and Microsoft Sentinel.

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Forcunsami%2FSOCRadar-Azure-Incidents%2Fmaster%2Fazuredeploy.json)

## Prerequisites

- Microsoft Sentinel workspace
- SOCRadar API Key

## Configuration

### Required Parameters

| Parameter | Description |
|-----------|-------------|
| `WorkspaceName` | Your Sentinel workspace name (e.g., `my-sentinel-workspace`, NOT the Workspace ID/GUID) |
| `WorkspaceLocation` | Region of your workspace (e.g., `centralus`, `northeurope`) |
| `SocradarApiKey` | Your SOCRadar API key |
| `CompanyId` | Your SOCRadar company ID |

> **Note:** You can find your Workspace Name in Azure Portal > Log Analytics workspaces > your workspace > Overview > "Name" field.

### Optional Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `PollingIntervalMinutes` | 5 | How often to check for alarms (1-60 min) |
| `InitialLookbackMinutes` | 600 | First run lookback (default: 10 hours) |
| `EnableAuditLogging` | true | Log operations to Log Analytics |
| `EnableAlarmsTable` | true | Store alarms in SOCRadar_Alarms_CL table for analytics |
| `EnableWorkbook` | true | Deploy SOCRadar Analytics Dashboard |
| `TableRetentionDays` | 365 | Data retention (30-730 days) |

## What Gets Deployed

- **SOCRadar-Alarm-Import** - Imports alarms from SOCRadar as Sentinel incidents
- **SOCRadar-Alarm-Sync** - Syncs closed incidents back to SOCRadar
- **SOCRadar_Alarms_CL** - Custom table for alarm analytics (if EnableAlarmsTable=true)
- **SOCRadar Analytics Dashboard** - Workbook with charts and tables (if EnableWorkbook=true)
- **SOCRadarAuditLog_CL** - Audit log table (if EnableAuditLogging=true)
- **Data Collection Endpoint & Rules** - For data ingestion

## Key Features

**Alarm Import**
- Automatically imports SOCRadar alarms as Sentinel incidents
- Severity and status mapping
- Duplicate prevention
- Tags for categorization

**Bidirectional Sync**
- Closed incidents in Sentinel update alarm status in SOCRadar
- Classification mapping: TruePositive to Resolved, FalsePositive to False Positive

**Audit Logging**
- Full alarm JSON stored in Log Analytics
- Query with KQL for reporting

**Analytics Dashboard**
- Severity and status distribution charts
- Alarm timeline visualization
- Top alarm types bar chart
- Recent alarms table

**KQL Queries**
- See `socradar-kql-queries.kql` for 24 ready-to-use queries including:
  - Alarm overview and trends
  - Incident correlation
  - Audit log analysis
  - Alert rules for scheduled analytics

## Post-Deployment

Logic Apps are configured to start **3 minutes after deployment** to allow Azure role propagation.

No manual action required - they will start automatically.

## About SOCRadar

SOCRadar is an Extended Threat Intelligence (XTI) platform that provides actionable threat intelligence, digital risk protection, and external attack surface management.

Learn more at [socradar.io](https://socradar.io)

## Support

- **Documentation:** [docs.socradar.io](https://docs.socradar.io)
- **Support:** support@socradar.io
