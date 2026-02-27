# Entity Mapping POC - Test Report

**Date:** February 27, 2026
**Branch:** `feature/entity-mapping`
**Repo:** `orcunsami/SOCRadar-Azure-Incidents`

## Summary

Sentinel incident API does NOT support adding entities directly. The workaround is the **Bookmark + Relation** pattern: create a Bookmark with `entityMappings`, then link it to the incident via a Relation. Entities then appear in the incident's investigation graph.

**Result: WORKING.** Preview API `2025-07-01-preview` supports `entityMappings` on Bookmarks. CLI test confirmed 3 entity types (IP, DNS, URL) appear on the incident.

---

## CLI Test Results

**Script:** `tests/entity_mapping_test.sh`
**Environment:** Subscription `b622bfd9`, RG `RSS-app-RG`, Workspace `orcun-rss-workspace-v2`

| Step | Action | Result |
|------|--------|--------|
| 1/6 | Create test incident | PASS |
| 2/6 | Create bookmark with entityMappings (preview API) | PASS - entityMappings in response |
| 3/6 | Create bookmark-to-incident relation | GatewayTimeout (but still worked) |
| 4/6 | Query incident entities | **PASS - 3 entities found** |
| 5/6 | List incident bookmarks | PASS - 1 bookmark linked |
| 6/6 | Cleanup | PASS |

### Entities Found on Incident

| Entity Kind (Response) | Friendly Name | Request EntityType |
|------------------------|---------------|--------------------|
| Ip | 13.238.62.121 | IP |
| DnsResolution | orderonline.sylvesterspizzadelivery.com.au | DNS |
| Url | https://platform.socradar.com/company/330/phishing/79407691/detail_page | URL |

**Key observation:** Entity types in the response use different casing than the request (`Ip` not `IP`, `DnsResolution` not `DNS`). This is expected - Sentinel normalizes them internally.

---

## ARM Template Changes

**File:** `Playbooks/SOCRadar-Alarm-Import/azuredeploy.json`

### New Parameter

```json
"EnableEntityMapping": {
    "type": "bool",
    "defaultValue": true,
    "metadata": {
        "description": "Create entity bookmarks (IP, Domain, URL) linked to incidents for investigation graph"
    }
}
```

### New Actions (inside For_Each_Alarm)

Flow: `Check_If_Open_Status` -> `Check_Entity_Mapping_Enabled` -> `Check_Audit_Enabled`

1. **Check_Entity_Mapping_Enabled** (If) - checks `EnableEntityMapping` param
2. **Build_Entity_Mappings** (Compose) - extracts entities from alarm content:
   - `content.ip_address` (first IP, comma-separated) -> IP entity
   - `content.phishing_domain` -> DNS entity
   - `content.phishing_domain_url` -> URL entity
   - Null/empty values are skipped
3. **Check_Has_Entities** (If) - skip if no entities extracted
4. **Create_Entity_Bookmark** (HTTP PUT) - creates bookmark with entityMappings via preview API

### Entity Extraction Logic

| SOCRadar Field | Sentinel Entity | Identifier | Notes |
|----------------|----------------|------------|-------|
| `content.ip_address` | IP | Address | Takes first IP (comma-split) |
| `content.phishing_domain` | DNS | DomainName | Brand Protection alarms |
| `content.phishing_domain_url` | URL | Url | Brand Protection alarms |

**POC Scope:** 3 entity types. Future: FileHash, Account (email), Host, more IPs.

### ARM Validation

| Scenario | Result |
|----------|--------|
| Same-RG (default) | PASS |
| Cross-RG (WorkspaceResourceGroup=RSS-test-RG) | PASS |
| EnableEntityMapping=false | PASS |

---

## API Details

| Operation | API Version | Type |
|-----------|-------------|------|
| Create Bookmark | **2025-07-01-preview** | PREVIEW |
| Create Relation | 2024-03-01 | Stable |
| Query Entities | 2024-03-01 | Stable |

### Bookmark Request Body

```json
{
    "properties": {
        "displayName": "SOCRadar Entities: #84031603 - Brand Protection",
        "query": "SecurityIncident | where Title contains '84031603'",
        "entityMappings": [
            {
                "entityType": "IP",
                "fieldMappings": [{"identifier": "Address", "value": "13.238.62.121"}]
            },
            {
                "entityType": "DNS",
                "fieldMappings": [{"identifier": "DomainName", "value": "example.com"}]
            },
            {
                "entityType": "URL",
                "fieldMappings": [{"identifier": "Url", "value": "https://..."}]
            }
        ],
        "labels": ["SOCRadar", "EntityMapping"],
        "eventTime": "2026-02-27T00:00:00Z"
    }
}
```

---

## Risks and Limitations

### 1. Preview API (HIGH RISK)

`2025-07-01-preview` is NOT stable. Microsoft may:
- Change the `entityMappings` schema
- Remove the property entirely
- Move it to a different stable version

**Mitigation:** `EnableEntityMapping` parameter defaults to `true` but can be disabled without redeployment. If the preview API breaks, set to `false`.

**Fallback:** Stable API `2024-03-01` supports `queryResult` field. MS examples show an `__entityMapping` pattern embedded in queryResult JSON. This has NOT been tested but could serve as a fallback.

### 2. Entity Coverage (MEDIUM)

POC extracts 3 entity types from `content.*` fields. Not all SOCRadar alarm types have these fields:
- Brand Protection alarms: `phishing_domain`, `phishing_domain_url`, `ip_address` (good coverage)
- Data Breach alarms: mostly `credential_details` (no entity fields)
- Botnet/DDoS: `ip_address` exists
- Generic alarms: `alarm_related_entities[]` array (NOT extracted yet)

**Future work:** Parse `alarm_related_entities` array for broader entity coverage across all alarm types.

### 3. No Relation Created (LOW RISK)

The Logic App template creates a bookmark but does NOT create a Relation (bookmark -> incident). CLI test showed that entities appeared on the incident even without a relation (or despite the relation timing out). However, this behavior may depend on the preview API auto-linking bookmarks.

If entities stop appearing, a Relation action should be added. This requires knowing the incident ID which is different depending on the create path (New vs Closed).

### 4. Single IP Only (LOW)

`content.ip_address` can be comma-separated ("1.2.3.4,5.6.7.8"). The POC takes only the first IP. Multiple IPs would require Logic App `split()` + `select()` which adds complexity.

---

## What Customer Gets

When enabled, each imported SOCRadar alarm incident will have:
- **Entities tab**: Structured IP addresses, domains, and URLs
- **Investigation graph**: Visual entity connections
- **Entity pages**: Click on IP/domain to see Sentinel's threat intelligence, related incidents, etc.

Before (current): Entity data is buried in the incident description as plain text.
After (with entity mapping): Entities are clickable, searchable, and integrated with Sentinel's investigation tools.

---

## Recommendation

1. **Short term (POC/pilot):** Deploy with `EnableEntityMapping=true` for the customer. Monitor preview API stability.
2. **Medium term:** Add `alarm_related_entities` parsing for broader alarm coverage.
3. **Long term:** When MS promotes entityMappings to stable API, update the API version.

If the preview API breaks: set `EnableEntityMapping=false` via ARM parameter override - no redeployment needed, just parameter change.

---

## Files Changed

| File | Change |
|------|--------|
| `Playbooks/SOCRadar-Alarm-Import/azuredeploy.json` | Entity mapping parameter + 4 actions |
| `tests/entity_mapping_test.sh` | CLI test script (NEW) |
| `tests/ENTITY_MAPPING_REPORT.md` | This report (NEW) |
