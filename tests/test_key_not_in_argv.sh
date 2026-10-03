#!/usr/bin/env bash
# scripts/test_deploy_paths.sh must not put SocradarApiKey in az's argv (visible in ps).
# Fake az logs argv; the key canary must be absent from argv and output, the param file
# 0600 and gone at exit. Then mutates the script back to the old form: the check must FAIL.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS="$HERE/../scripts"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
CANARY="canary-KEY-$RANDOM$RANDOM-zz"
mkdir "$T/bin"
cat > "$T/bin/az" <<'FAKE'
#!/usr/bin/env bash
printf '%s\n' "az $*" >> "$T/argv.log"
if [ "$1 $2 $3" = "deployment group create" ]; then
    for a in "$@"; do case "$a" in @*) f="${a#@}"
        echo "PERM=$(stat -c %a "$f") HASKEY=$(grep -c "$CANARY" "$f") FILE=$f" >> "$T/meta.log";; esac; done
fi
exit 0
FAKE
chmod +x "$T/bin/az"

check() {  # check <script path>; returns 0 if the key stayed out of argv
    rm -f "$T/argv.log" "$T/meta.log"; : > "$T/argv.log"; : > "$T/meta.log"
    ( export T CANARY PATH="$T/bin:$PATH" TEST_COMPANY_ID=1 TEST_SOCRADAR_API_KEY="$CANARY"
      bash -x "$1" ) > "$T/out.log" 2>&1
    local ok=0 f
    grep -q 'az deployment group create' "$T/argv.log" || { echo "  no deployment call seen"; return 1; }
    grep -q "$CANARY" "$T/argv.log" && { echo "  canary in argv"; ok=1; }
    grep -q "$CANARY" "$T/out.log" && { echo "  canary in output"; ok=1; }
    [ "$(grep -c 'PERM=600 HASKEY=1' "$T/meta.log")" = "$(grep -c 'az deployment group create' "$T/argv.log")" ] \
        || { echo "  a deployment call without a 0600 key file"; ok=1; }
    f=$(sed 's/.*FILE=//' "$T/meta.log" | head -1)
    [ -n "$f" ] && [ -e "$f" ] && { echo "  param file left behind"; ok=1; }
    [ -n "$f" ] && rm -f "$f"
    return $ok
}

fails=0
echo "real test_deploy_paths.sh:"
check "$SCRIPTS/test_deploy_paths.sh" && echo "  PASS" || { echo "  FAIL"; fails=1; }

mutant() {  # mutant <name> <sed expr>
    local M="$SCRIPTS/.paths.mut.$$.sh"
    sed "$2" "$SCRIPTS/test_deploy_paths.sh" > "$M"
    if cmp -s "$M" "$SCRIPTS/test_deploy_paths.sh"; then echo "mutant $1: mutation did not apply"; fails=1; rm -f "$M"; return; fi
    echo "mutant $1 (expected to FAIL):"
    check "$M"; local rc=$?; rm -f "$M"
    [ $rc -ne 0 ] && echo "  caught" || { echo "  NOT caught"; fails=1; }
}
mutant argv-form 's|@"\$PARAMS_FILE"|SocradarApiKey="$API_KEY"|'
mutant no-cleanup '/^trap .rm -f/d;/^    rm -f "\$PARAMS_FILE"$/d'
exit $fails
