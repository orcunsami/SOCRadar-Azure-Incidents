#!/usr/bin/env bash
# Regression test for EXP-AZURE-0198. A wrong WorkspaceName with the parameters
# left at their defaults used to half-install: five resources created, including
# an enabled and billable Logic App, and only then a ResourceNotFound.
#
# It shipped that way because every greenfield E2E ran with
# DeployNewWorkspace=true -- a fresh workspace is what a greenfield test needs --
# so the path a customer actually clicks, the defaults, was never run. This
# script runs it, and runs the guard's success branch too, because the guard is
# SKIPPED on the happy path: a wrong api-version or field name inside it would
# leave every test green and fail only at a customer.
#
# Six paths, each asserting a different thing:
#   A  missing workspace, defaults  -> deployment fails, resource group stays EMPTY
#   B  same RG, DeployNewWorkspace=true -> succeeds, guard skipped
#   C  existing workspace, cross-RG     -> guard SUCCEEDS and resolves customerId
#   D  A's resource group after B       -> the guard does not block a redeploy
#   E  cross-RG onto a workspace with no Microsoft Sentinel -> rejected, nothing created
#   F  AlertBacked cross-RG                 -> rejected during validation
#
# Run before pushing any change to the resource graph of azuredeploy.json.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TEMPLATE="$REPO_ROOT/azuredeploy.json"

LOCATION="${TEST_LOCATION:-westeurope}"
COMPANY_ID="${TEST_COMPANY_ID:?set TEST_COMPANY_ID}"
API_KEY="${TEST_SOCRADAR_API_KEY:?set TEST_SOCRADAR_API_KEY}"
KEEP="${KEEP_RESOURCES:-false}"

SFX=$(python3 -c "import uuid;print(uuid.uuid4().hex[:4])")
RG_APP="rg-deploy-paths-$SFX"
RG_WS="rg-deploy-paths-ws-$SFX"
WS="ws-deploy-paths-$SFX"
MISSING="ws-does-not-exist-$SFX"

fails=0
row() {  # row <name> <PASS|FAIL> <detail>
    printf '%-34s %-5s %s\n' "$1" "$2" "$3"
    [ "$2" = PASS ] || fails=$((fails + 1))
}

cleanup() {
    if [ "$KEEP" = true ]; then
        echo "KEEP_RESOURCES=true, leaving $RG_APP, $RG_WS, ${RG_BARE:-} and ${RG_E:-} in place"
        return
    fi
    for rg in "$RG_APP" "$RG_WS" "${RG_BARE:-}" "${RG_E:-}"; do
        [ -n "$rg" ] || continue
        az group delete -n "$rg" --yes --no-wait -o none 2>/dev/null
    done
    echo "cleanup: delete queued for $RG_APP, $RG_WS, ${RG_BARE:-} and ${RG_E:-}"
}
trap cleanup EXIT

start_time() { python3 -c "import datetime;print((datetime.datetime.now(datetime.UTC)+datetime.timedelta(minutes=180)).strftime('%Y-%m-%dT%H:%M:%SZ'))"; }

deploy() {  # deploy <rg> <name> <extra params...>
    local rg="$1" name="$2"; shift 2
    az deployment group create -g "$rg" -n "$name" --template-file "$TEMPLATE" \
        --parameters CompanyId="$COMPANY_ID" SocradarApiKey="$API_KEY" \
                     WorkspaceLocation="$LOCATION" _triggerStartTime="$(start_time)" "$@" \
        -o none 2>/dev/null
}

echo "[1/5] Creating $RG_APP and $RG_WS ..."
az group create -n "$RG_APP" -l "$LOCATION" -o none
az group create -n "$RG_WS"  -l "$LOCATION" -o none

# --- A: the customer's typo, defaults left alone --------------------------------------
echo "[2/5] Path A: missing workspace with the parameters at their defaults ..."
deploy "$RG_APP" path-a WorkspaceName="$MISSING" WorkspaceResourceGroup="$RG_APP"
state=$(az deployment group show -g "$RG_APP" -n path-a --query properties.provisioningState -o tsv 2>/dev/null)
left=$(az resource list -g "$RG_APP" --query "length(@)" -o tsv 2>/dev/null)
failed_steps=$(az deployment operation group list -g "$RG_APP" -n path-a \
    --query "[?properties.provisioningState=='Failed'].properties.targetResource.resourceName" -o tsv 2>/dev/null \
    | grep -c 'precheck-workspace-exists')

[ "$state" = Failed ] \
    && row "A deployment fails" PASS "$state" \
    || row "A deployment fails" FAIL "expected Failed, got '${state:-<unreadable>}'"
# The whole point: nothing may exist afterwards. This is the assertion that used to be 5.
[ "${left:-x}" = 0 ] \
    && row "A leaves nothing behind" PASS "0 resources" \
    || row "A leaves nothing behind" FAIL "expected 0 resources, found '${left:-<unreadable>}' - the guard did not hold"
[ "${failed_steps:-0}" -ge 1 ] \
    && row "A blames the precheck" PASS "precheck-workspace-exists" \
    || row "A blames the precheck" FAIL "the precheck was not the failing step"

# --- B: greenfield, the mode every earlier E2E used ------------------------------------
echo "[3/5] Path B: DeployNewWorkspace=true in the same resource group ..."
deploy "$RG_APP" path-b WorkspaceName="$WS" WorkspaceResourceGroup="$RG_APP" DeployNewWorkspace=true
state=$(az deployment group show -g "$RG_APP" -n path-b --query properties.provisioningState -o tsv 2>/dev/null)
[ "$state" = Succeeded ] \
    && row "B greenfield succeeds" PASS "$state" \
    || row "B greenfield succeeds" FAIL "expected Succeeded, got '${state:-<unreadable>}'"
# The guard must not run here: it would look for a workspace this deployment creates.
guard_ran=$(az deployment operation group list -g "$RG_APP" -n path-b \
    --query "[?properties.targetResource.resourceName=='precheck-workspace-exists'] | length(@)" -o tsv 2>/dev/null)
[ "${guard_ran:-x}" = 0 ] \
    && row "B skips the precheck" PASS "condition false" \
    || row "B skips the precheck" FAIL "the precheck ran against a workspace being created"

# --- C: the guard's success branch, which B never exercises ----------------------------
echo "[4/5] Path C: existing workspace in another resource group ..."
az monitor log-analytics workspace create -g "$RG_WS" -n "$WS" -l "$LOCATION" --retention-time 30 -o none 2>/dev/null
deploy "$RG_WS" path-c WorkspaceName="$WS" WorkspaceResourceGroup="$RG_WS" DeployNewWorkspace=false
guard_state=$(az deployment operation group list -g "$RG_WS" -n path-c \
    --query "[?properties.targetResource.resourceName=='precheck-workspace-exists'].properties.provisioningState" -o tsv 2>/dev/null)
[ "$guard_state" = Succeeded ] \
    && row "C precheck succeeds" PASS "$guard_state" \
    || row "C precheck succeeds" FAIL "expected Succeeded, got '${guard_state:-<unreadable>}' - reference() may name a field or api-version that does not exist"
# Reading the output proves reference() resolved a real value rather than an empty string.
ws_id=$(az deployment group show -g "$RG_WS" -n precheck-workspace-exists \
    --query "properties.outputs.workspaceId.value" -o tsv 2>/dev/null)
printf '%s' "${ws_id:-}" | grep -Eq '^[0-9a-f]{8}-' \
    && row "C precheck resolves customerId" PASS "looks like a guid" \
    || row "C precheck resolves customerId" FAIL "output was '${ws_id:-<empty>}'"

# --- D: the guard must not block a second, correct deployment --------------------------
echo "[5/5] Path D: redeploying B's resource group ..."
deploy "$RG_APP" path-d WorkspaceName="$WS" WorkspaceResourceGroup="$RG_APP" DeployNewWorkspace=false
state=$(az deployment group show -g "$RG_APP" -n path-d --query properties.provisioningState -o tsv 2>/dev/null)
[ "$state" = Succeeded ] \
    && row "D redeploy succeeds" PASS "$state" \
    || row "D redeploy succeeds" FAIL "expected Succeeded, got '${state:-<unreadable>}' - the guard blocks a workspace that exists"

# --- E: the two cross-RG ways to look green and be dead ---------------------------------
echo "[6/7] Path E: cross-RG onto a workspace with no Microsoft Sentinel ..."
RG_BARE="rg-deploy-paths-bare-$SFX"
az group create -n "$RG_BARE" -l "$LOCATION" -o none
az monitor log-analytics workspace create -g "$RG_BARE" -n "ws-bare-$SFX" -l "$LOCATION" --retention-time 30 -o none 2>/dev/null
RG_E="rg-deploy-paths-e-$SFX"
az group create -n "$RG_E" -l "$LOCATION" -o none
deploy "$RG_E" path-e WorkspaceName="ws-bare-$SFX" WorkspaceResourceGroup="$RG_BARE" DeployNewWorkspace=false
state=$(az deployment group show -g "$RG_E" -n path-e --query properties.provisioningState -o tsv 2>/dev/null)
left=$(az resource list -g "$RG_E" --query "length(@)" -o tsv 2>/dev/null)
[ "$state" = Failed ] \
    && row "E rejects un-onboarded workspace" PASS "$state" \
    || row "E rejects un-onboarded workspace" FAIL "expected Failed, got '${state:-<unreadable>}' - a green deploy here means a dead integration"
[ "${left:-x}" = 0 ] \
    && row "E leaves nothing behind" PASS "0 resources" \
    || row "E leaves nothing behind" FAIL "expected 0, found '${left:-<unreadable>}'"

echo "[7/7] Path F: AlertBacked cross-RG ..."
out=$(az deployment group create -g "$RG_E" -n path-f --template-file "$TEMPLATE" \
        --parameters CompanyId="$COMPANY_ID" SocradarApiKey="$API_KEY" \
                     WorkspaceLocation="$LOCATION" _triggerStartTime="$(start_time)" \
                     WorkspaceName="$WS" WorkspaceResourceGroup="$RG_WS" \
                     DeployNewWorkspace=false IncidentMode=AlertBacked -o none 2>&1)
# allowedValues on the inner parameter rejects this during validation, so nothing is created.
printf '%s' "$out" | grep -q "not part of the allowed value" \
    && row "F rejects AlertBacked cross-RG" PASS "validation error" \
    || row "F rejects AlertBacked cross-RG" FAIL "expected an allowedValues rejection, got: $(printf '%s' "$out" | head -c 120)"
left=$(az resource list -g "$RG_E" --query "length(@)" -o tsv 2>/dev/null)
[ "${left:-x}" = 0 ] \
    && row "F leaves nothing behind" PASS "0 resources" \
    || row "F leaves nothing behind" FAIL "expected 0, found '${left:-<unreadable>}'"

echo
if [ "$fails" -eq 0 ]; then
    echo "All six deployment paths behaved as asserted."
else
    echo "$fails assertion(s) failed."
fi
exit $((fails == 0 ? 0 : 1))
