# tests/

Offline checks against the live SOCRadar API. Nothing here touches Azure.

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

### 2026-08-19 finding (preprod company 132, last 30 days, 803 alarms)

- severity: MEDIUM 98.8%, CRITICAL 0.7%, HIGH 0.2%, LOW 0.2%. HIGH/CRITICAL
  exist, just rare - the analytic rule was never proven firing because our
  test window (408 alarms) happened to contain none.
- size: average alarm 251 KB, largest 1264 KB. A single 100-alarm API page is
  8.7-34.2 MB. This is independent of the K4 fix (raw accumulation across
  pages) - it is the size of one page, one HTTP action call.
