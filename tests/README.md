# tests/

Template checks that run in CI, plus one script that measures the live SOCRadar API.
Nothing here deploys anything to Azure.

## Template checks (CI)

`.github/workflows/template-checks.yml` runs all of these on every push and PR. They read the
templates and fail on a contract that no ARM validation can see, because ARM validates JSON
shape and never runs a workflow action.

| Check | What it pins |
|---|---|
| `../tools/check_expressions.py` | Every Logic App expression parses, and its function calls exist |
| `../tools/check_template_drift.py` | The standalone playbooks have not fallen behind `azuredeploy.json` |
| `../tools/check_analytic_rules.py` | The shipped analytic rules are well formed |
| `test_checkpoint.py` | The import window comes from the storage checkpoint, not from incident titles: the account's name and security properties, the role assignment's scope, the GET/PUT headers Table Storage requires, and that the checkpoint is written only after a complete read |
| `../tools/check_commit_hygiene.sh` | Before pushing: fails when a commit message in `master..HEAD` carries a company id, a workspace or resource group name, an alarm id or a tool signature. Runs in CI too; `--msg-file` makes it a `commit-msg` hook |
| `test_daily_rescan.py` | The shipped lookback expression, evaluated at fixed clock times: once a day after 09:00 UTC it reaches back 5 days, otherwise the gap since the last run, never past 7 days; no parameter exposes it; Direct mode imports nothing while the existing-incident list is cut short; every SOCRadar call of the import sends a User-Agent |
| `mutate_daily_rescan.py` | Breaks the rescan in 10 ways in both template copies; the rescan test must fail each one |
| `test_lookback_bounds.py` | `InitialLookbackMinutes` is bounded 10 to 10080 in the combined template and the standalone import playbook, the default sits inside, and 10080 is the clamp in `Determine_Lookback` |
| `mutate_lookback_bounds.py` | Moves each bound and the clamp in both template copies (6 mutations); the bounds test must fail each one |
| `test_severity_sync_logic.py` | The severity write-back can only raise a severity, is gated by `SyncSeverity`, is judged by `is_success`, and that both label builders carry the labels Sync reads |
| `test_management_base_url.py` | No template hardcodes the public-cloud ARM host |
| `test_hunting_queries.py` | Every column the hunting queries read is one the deployment creates |
| `test_cross_rg_roles.py` | The cross-RG nested role assignments grant the import identity the same elevated role the same-RG path grants, so IoC enrichment does not silently 403 when the workspace lives in another resource group |
| `test_import_integrity.py` | The import cannot lose alarms or duplicate incidents silently |
| `test_incident_dedup.py` | Every `SecurityIncident` query collapses to the newest version of each incident |
| `test_incident_dedup_projection.py` | The existing-incident page is projected to the fields its consumers read |
| `test_domain_tld_whitelist.py` | Domain entities are matched against real country codes, not any two letters |
| `test_alert_backed_mode.py` | Alert-backed mode: rule limits, import cap, checkpoint and the Sync entity reader |
| `test_sync_window.py` | Sync reaches back 24 hours, drops synced incidents before the loop, and a failed page fails the run |
| `test_query_logic.py` | The volume-spike rule, the not-yet-closed query and the Alarm Overview query do what the README says |
| `test_description_markdown.py` | The incident description is markdown-safe: content table, escaped alarm text, caps applied after escaping, whole description cut at 5000 |
| `test_alarm_link.py` | The View in SOCRadar link opens the alarm (tab from approval) and Sync reads the alarm id from both the new and the old SOCRadar URL |

Run them all locally:

```
for f in tools/check_*.py tests/test_*.py; do python3 "$f" || break; done
```

## Live API measurement

## check_alarm_severity.py

Answers one question: what severities do real alarms actually carry, and how
big are they. Used to decide whether the analytic rules in `Analytic Rules/`
can ever fire on real data, and whether the import playbook's page size is
safe.

```
export SOCRADAR_API_KEY=...
export SOCRADAR_COMPANY_ID=...
python3 check_alarm_severity.py --days 30
```

Writes a JSON report next to the script. That report is gitignored
(`tests/*.json`) because it can contain live alarm data.

### 2026-08-19 finding (preprod tenant, last 30 days, 803 alarms)

- severity: MEDIUM 98.8%, CRITICAL 0.7%, HIGH 0.2%, LOW 0.2%. HIGH/CRITICAL
  exist, just rare - the analytic rule was never proven firing because our
  test window (408 alarms) happened to contain none.
- size: average alarm 251 KB, largest 1264 KB. A single 100-alarm API page is
  8.7-34.2 MB. This is independent of the K4 fix (raw accumulation across
  pages) - it is the size of one page, one HTTP action call.
