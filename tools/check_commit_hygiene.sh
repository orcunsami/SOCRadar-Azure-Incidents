#!/usr/bin/env bash
# Pre-push gate: commit messages must not carry customer or test-environment identifiers
# or AI signatures. Scans subject and body of every commit in a range.
#
#   tools/check_commit_hygiene.sh                # master..HEAD
#   tools/check_commit_hygiene.sh <range>        # any git range
#   tools/check_commit_hygiene.sh --msg-file F   # one message file (commit-msg hook)
#
# Extra, non-generic terms (names that should not be written into this tracked file) go one
# per line, as extended regexes, into .git/commit-hygiene-extra (untracked, local).
set -u
cd "$(git rev-parse --show-toplevel)" || exit 2

PATTERNS=(
  'company[ -]?[0-9]+'            # company ids
  '\blaw-[a-z0-9]'                # Log Analytics workspace names
  'rg-e2e'                        # test resource groups
  '\b1[0-9]{8}\b'                 # 9-digit alarm ids
  '999[0-9]{6}'                   # synthetic alarm ids
  'claude|anthropic|co-authored-by|generated with'
)
EXTRA="$(git rev-parse --git-dir)/commit-hygiene-extra"
if [ -f "$EXTRA" ]; then
  while IFS= read -r line; do [ -n "$line" ] && PATTERNS+=("$line"); done < "$EXTRA"
fi
RE="$(IFS='|'; echo "${PATTERNS[*]}")"

if [ "${1:-}" = "--msg-file" ]; then
  text="$(cat "${2:?message file}")"
  hits="$(printf '%s\n' "$text" | grep -n -i -E "$RE" || true)"
else
  range="${1:-master..HEAD}"
  hits="$(git log --format='@@ %h %s%n%b' "$range" | awk '/^@@ /{c=$2; sub(/^@@ [^ ]+ /,""); print c ": " $0; next} {print c ": " $0}' | grep -i -E "$RE" || true)"
fi

if [ -n "$hits" ]; then
  echo "commit hygiene: FAIL, identifiers or signatures in commit messages:"
  echo "$hits"
  exit 1
fi
echo "commit hygiene: OK"
