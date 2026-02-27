#!/bin/bash
# Entity Mapping POC Test - Bookmark + Relation Pattern
# Tests whether Sentinel bookmarks with entityMappings create structured entities
# linked to incidents via the investigation graph.
#
# Usage: ./entity_mapping_test.sh
# Requires: az CLI logged in, Sentinel workspace onboarded

set -euo pipefail

# --- Configuration ---
SUBSCRIPTION_ID="b622bfd9-6b2b-45b3-b7d2-7b5d3114b96b"
RESOURCE_GROUP="RSS-app-RG"
WORKSPACE_NAME="orcun-rss-workspace-v2"

BASE_URL="https://management.azure.com/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.OperationalInsights/workspaces/${WORKSPACE_NAME}/providers/Microsoft.SecurityInsights"

# Generate unique IDs for this test run
INCIDENT_ID=$(uuidgen | tr '[:upper:]' '[:lower:]')
BOOKMARK_ID=$(uuidgen | tr '[:upper:]' '[:lower:]')
RELATION_ID=$(uuidgen | tr '[:upper:]' '[:lower:]')

# Test entity data (from sample SOCRadar alarm #84031603)
TEST_IP="13.238.62.121"
TEST_DOMAIN="orderonline.sylvesterspizzadelivery.com.au"
TEST_URL="https://platform.socradar.com/company/330/phishing/79407691/detail_page"

echo "========================================="
echo "Entity Mapping POC Test"
echo "========================================="
echo "Incident ID: ${INCIDENT_ID}"
echo "Bookmark ID: ${BOOKMARK_ID}"
echo "Relation ID: ${RELATION_ID}"
echo ""

# --- Test 1: Create test incident ---
echo "[1/6] Creating test incident..."
INCIDENT_RESULT=$(az rest --method PUT \
    --url "${BASE_URL}/incidents/${INCIDENT_ID}?api-version=2023-11-01" \
    --body "{
        \"properties\": {
            \"title\": \"[TEST] Entity Mapping POC - $(date +%H:%M)\",
            \"description\": \"Test incident for entity mapping POC. IP: ${TEST_IP}, Domain: ${TEST_DOMAIN}\",
            \"severity\": \"Medium\",
            \"status\": \"New\"
        }
    }" 2>&1) || true

if echo "$INCIDENT_RESULT" | grep -q '"name"'; then
    echo "  PASS: Incident created"
    INCIDENT_NAME=$(echo "$INCIDENT_RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin)['name'])" 2>/dev/null || echo "$INCIDENT_ID")
    echo "  Incident name: ${INCIDENT_NAME}"
else
    echo "  FAIL: Incident creation failed"
    echo "  Response: ${INCIDENT_RESULT}"
    echo ""
    echo "Aborting test."
    exit 1
fi

# --- Test 2: Create bookmark with entityMappings (preview API) ---
echo ""
echo "[2/6] Creating bookmark with entityMappings (preview API)..."
BOOKMARK_RESULT=$(az rest --method PUT \
    --url "${BASE_URL}/bookmarks/${BOOKMARK_ID}?api-version=2025-07-01-preview" \
    --body "{
        \"properties\": {
            \"displayName\": \"SOCRadar Entities: Test Alarm #84031603\",
            \"query\": \"SecurityIncident | where Title contains 'Entity Mapping POC'\",
            \"queryResult\": \"{\\\"IpAddress\\\":\\\"${TEST_IP}\\\",\\\"DomainName\\\":\\\"${TEST_DOMAIN}\\\"}\",
            \"entityMappings\": [
                {
                    \"entityType\": \"IP\",
                    \"fieldMappings\": [{\"identifier\": \"Address\", \"value\": \"${TEST_IP}\"}]
                },
                {
                    \"entityType\": \"DNS\",
                    \"fieldMappings\": [{\"identifier\": \"DomainName\", \"value\": \"${TEST_DOMAIN}\"}]
                },
                {
                    \"entityType\": \"URL\",
                    \"fieldMappings\": [{\"identifier\": \"Url\", \"value\": \"${TEST_URL}\"}]
                }
            ],
            \"labels\": [\"SOCRadar\", \"EntityMapping\"],
            \"eventTime\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"
        }
    }" 2>&1) || true

if echo "$BOOKMARK_RESULT" | grep -q '"name"'; then
    echo "  PASS: Bookmark created with entityMappings"
    BOOKMARK_NAME=$(echo "$BOOKMARK_RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin)['name'])" 2>/dev/null || echo "$BOOKMARK_ID")
    echo "  Bookmark name: ${BOOKMARK_NAME}"

    # Check if entityMappings are in the response
    if echo "$BOOKMARK_RESULT" | grep -q "entityMappings"; then
        echo "  PASS: entityMappings present in response"
    else
        echo "  WARN: entityMappings NOT in response (may be write-only or ignored)"
    fi
else
    echo "  FAIL: Bookmark creation failed"
    echo "  Response: ${BOOKMARK_RESULT}"
    echo ""
    echo "  Trying fallback: stable API without entityMappings..."

    # Fallback: try stable API with queryResult only
    BOOKMARK_RESULT=$(az rest --method PUT \
        --url "${BASE_URL}/bookmarks/${BOOKMARK_ID}?api-version=2024-03-01" \
        --body "{
            \"properties\": {
                \"displayName\": \"SOCRadar Entities: Test Alarm #84031603\",
                \"query\": \"SecurityIncident | where Title contains 'Entity Mapping POC'\",
                \"queryResult\": \"{\\\"IpAddress\\\":\\\"${TEST_IP}\\\",\\\"DomainName\\\":\\\"${TEST_DOMAIN}\\\",\\\"Url\\\":\\\"${TEST_URL}\\\",\\\"__entityMapping\\\":{\\\"${TEST_IP}\\\":\\\"IP\\\",\\\"${TEST_DOMAIN}\\\":\\\"Host\\\"}}\",
                \"labels\": [\"SOCRadar\", \"EntityMapping\"],
                \"eventTime\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"
            }
        }" 2>&1) || true

    if echo "$BOOKMARK_RESULT" | grep -q '"name"'; then
        echo "  PASS: Bookmark created (stable API, queryResult fallback)"
        BOOKMARK_NAME=$(echo "$BOOKMARK_RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin)['name'])" 2>/dev/null || echo "$BOOKMARK_ID")
    else
        echo "  FAIL: Both preview and stable bookmark creation failed"
        echo "  Response: ${BOOKMARK_RESULT}"
    fi
fi

# --- Test 3: Create relation (bookmark -> incident) ---
echo ""
echo "[3/6] Creating bookmark-to-incident relation..."
INCIDENT_RESOURCE_ID="/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.OperationalInsights/workspaces/${WORKSPACE_NAME}/providers/Microsoft.SecurityInsights/incidents/${INCIDENT_ID}"

RELATION_RESULT=$(az rest --method PUT \
    --url "${BASE_URL}/bookmarks/${BOOKMARK_ID}/relations/${RELATION_ID}?api-version=2024-03-01" \
    --body "{
        \"properties\": {
            \"relatedResourceId\": \"${INCIDENT_RESOURCE_ID}\"
        }
    }" 2>&1) || true

if echo "$RELATION_RESULT" | grep -q '"name"'; then
    echo "  PASS: Relation created (bookmark linked to incident)"
    echo "  Relation type: $(echo "$RELATION_RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('properties',{}).get('relatedResourceType','unknown'))" 2>/dev/null)"
else
    echo "  FAIL: Relation creation failed"
    echo "  Response: ${RELATION_RESULT}"
fi

# --- Test 4: Verify entities via incident entities endpoint ---
echo ""
echo "[4/6] Querying incident entities..."
ENTITIES_RESULT=$(az rest --method POST \
    --url "${BASE_URL}/incidents/${INCIDENT_ID}/entities?api-version=2024-03-01" \
    --body "{}" 2>&1) || true

if echo "$ENTITIES_RESULT" | grep -q '"entities"'; then
    ENTITY_COUNT=$(echo "$ENTITIES_RESULT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('entities',[])))" 2>/dev/null || echo "?")
    echo "  Entity count: ${ENTITY_COUNT}"

    if [ "$ENTITY_COUNT" != "0" ] && [ "$ENTITY_COUNT" != "?" ]; then
        echo "  PASS: Entities found on incident!"
        echo ""
        echo "  Entity details:"
        echo "$ENTITIES_RESULT" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for e in data.get('entities', []):
    kind = e.get('kind', 'unknown')
    name = e.get('properties', {}).get('friendlyName', 'N/A')
    print(f'    - {kind}: {name}')
" 2>/dev/null || echo "  (Could not parse entity details)"
    else
        echo "  WARN: No entities found (may need time to propagate, or entityMappings not creating entities)"
    fi
else
    echo "  WARN: Entities endpoint returned unexpected response"
    echo "  Response: $(echo "$ENTITIES_RESULT" | head -c 500)"
fi

# --- Test 5: List incident bookmarks ---
echo ""
echo "[5/6] Listing incident bookmarks..."
BOOKMARKS_RESULT=$(az rest --method POST \
    --url "${BASE_URL}/incidents/${INCIDENT_ID}/bookmarks?api-version=2024-03-01" \
    --body "{}" 2>&1) || true

if echo "$BOOKMARKS_RESULT" | grep -q '"value"'; then
    BM_COUNT=$(echo "$BOOKMARKS_RESULT" | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('value',[])))" 2>/dev/null || echo "?")
    echo "  Bookmarks linked to incident: ${BM_COUNT}"
    if [ "$BM_COUNT" != "0" ]; then
        echo "  PASS: Bookmark successfully linked to incident"
    fi
else
    echo "  WARN: Bookmarks endpoint returned unexpected response"
fi

# --- Test 6: Cleanup ---
echo ""
echo "[6/6] Cleaning up test resources..."

# Delete bookmark (also deletes relation)
az rest --method DELETE \
    --url "${BASE_URL}/bookmarks/${BOOKMARK_ID}?api-version=2024-03-01" 2>/dev/null && \
    echo "  Bookmark deleted" || echo "  WARN: Bookmark delete failed"

# Delete incident
az rest --method DELETE \
    --url "${BASE_URL}/incidents/${INCIDENT_ID}?api-version=2023-11-01" 2>/dev/null && \
    echo "  Incident deleted" || echo "  WARN: Incident delete failed"

echo ""
echo "========================================="
echo "Test Complete"
echo "========================================="
echo ""
echo "Summary:"
echo "  - Incident creation: OK"
echo "  - Bookmark with entityMappings: Check output above"
echo "  - Relation linking: Check output above"
echo "  - Entity visibility: Check output above"
echo ""
echo "Next: Check Azure Portal > Sentinel > Incidents"
echo "  (before cleanup, re-run without cleanup step to inspect)"
