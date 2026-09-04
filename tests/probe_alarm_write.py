#!/usr/bin/env python3
"""Exercise the SOCRadar write endpoints against one named alarm, safely.

Sync writes two things back to SOCRadar: alarm status and alarm severity. Both
are POSTs that return HTTP 200 even when they reject the request, so the only
way to know an endpoint works is to call it and read the body. Doing that by
hand is how the wrong alarm gets mutated, so this script refuses to write until
it has read the target and confirmed it is the one you meant.

Order is always: read -> print -> assert preconditions -> write (only with
--apply) -> read back.

Reads SOCRADAR_API_KEY and SOCRADAR_COMPANY_ID from the environment. The key is
never passed on a command line and never printed, including in tracebacks.

Usage:
    export SOCRADAR_API_KEY=...
    export SOCRADAR_COMPANY_ID=...

    # read only, no write at all
    python3 probe_alarm_write.py --alarm-id 104160975

    # dry run: shows the exact request it would send
    python3 probe_alarm_write.py --alarm-id 104160975 --set-status 0

    # write, but only if the alarm is currently what you expect
    python3 probe_alarm_write.py --alarm-id 104160975 --set-status 0 \
        --expect-status FALSE_POSITIVE --apply

Valid --set-severity values (measured 4 Sep 2026): INFO, LOW, MEDIUM, HIGH,
CRITICAL. "Informational" is rejected with HTTP 200 + is_success false.
Valid --set-status values: 0 OPEN, 2 RESOLVED, 9 FALSE_POSITIVE, 12 MITIGATED.
"""

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

READ_URL = "https://platform.socradar.com/api/company/{company}/incidents/v4"
STATUS_URL = "https://platform.socradar.com/api/company/{company}/alarms/status/change"
SEVERITY_URL = "https://platform.socradar.com/api/company/{company}/alarm/severity"

SEVERITIES = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
STATUS_NAMES = {0: "OPEN", 2: "RESOLVED", 9: "FALSE_POSITIVE", 12: "MITIGATED"}
PAGE_LIMIT = 100


def _redact(text, secret):
    if secret and secret in text:
        text = text.replace(secret, "***REDACTED***")
    return text


def _request(url, key, method="GET", body=None):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"API-Key": key}
    if data:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.status, json.loads(resp.read().decode("utf-8"))


def read_alarm(company, key, alarm_id, days):
    """Find one alarm by id. Returns its dict, or None if it is not in the window."""
    start_epoch = int(time.time()) - days * 86400
    for page in range(1, 200 + 1):
        query = urllib.parse.urlencode(
            {"page": page, "limit": PAGE_LIMIT, "start_date": start_epoch}
        )
        _, body = _request(READ_URL.format(company=company) + "?" + query, key)
        data = body.get("data") or {}
        alarms = data.get("alarms") if isinstance(data, dict) else None
        if alarms is None:
            alarms = body.get("alarms") or (data if isinstance(data, list) else [])
        if not alarms:
            return None
        for alarm in alarms:
            if str(alarm.get("alarm_id")) == str(alarm_id):
                return alarm
    return None


def describe(alarm):
    details = alarm.get("alarm_type_details") or {}
    if not isinstance(details, dict):
        details = {}
    return {
        "alarm_id": alarm.get("alarm_id"),
        "risk_level": alarm.get("alarm_risk_level"),
        "status": alarm.get("status"),
        "main_type": details.get("alarm_main_type"),
        "title": str(details.get("alarm_sub_type") or details.get("alarm_type") or "")[:70],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--alarm-id", required=True)
    parser.add_argument("--days", type=int, default=30, help="how far back to scan for the id")
    parser.add_argument("--set-severity", choices=SEVERITIES)
    parser.add_argument("--set-status", type=int, choices=sorted(STATUS_NAMES))
    parser.add_argument("--expect-severity", help="refuse to write unless risk_level matches")
    parser.add_argument("--expect-status", help="refuse to write unless status matches")
    parser.add_argument("--apply", action="store_true", help="actually write (default: dry run)")
    args = parser.parse_args()

    key = os.environ.get("SOCRADAR_API_KEY")
    company = os.environ.get("SOCRADAR_COMPANY_ID")
    if not key or not company:
        print("SOCRADAR_API_KEY and SOCRADAR_COMPANY_ID must be set", file=sys.stderr)
        return 2

    try:
        alarm = read_alarm(company, key, args.alarm_id, args.days)
    except urllib.error.HTTPError as exc:
        print("read failed: HTTP %s %s" % (exc.code, _redact(str(exc.reason), key)), file=sys.stderr)
        return 1
    if alarm is None:
        print("alarm %s not found in the last %s days" % (args.alarm_id, args.days), file=sys.stderr)
        return 1

    before = describe(alarm)
    print("TARGET  %s" % json.dumps(before))

    if not args.set_severity and args.set_status is None:
        return 0

    # Preconditions are checked against what we just read, never against memory.
    for flag, want, got in (
        ("--expect-severity", args.expect_severity, before["risk_level"]),
        ("--expect-status", args.expect_status, before["status"]),
    ):
        if want and str(want).upper() != str(got).upper():
            print("REFUSED %s=%s but alarm has %s" % (flag, want, got), file=sys.stderr)
            return 3

    writes = []
    if args.set_severity:
        writes.append(
            (
                "severity",
                SEVERITY_URL.format(company=company),
                {"alarm_ids": [int(args.alarm_id)], "severity": args.set_severity},
            )
        )
    if args.set_status is not None:
        writes.append(
            (
                "status",
                STATUS_URL.format(company=company),
                {
                    "alarm_ids": [int(args.alarm_id)],
                    "status": str(args.set_status),
                    "comments": "probe_alarm_write.py",
                },
            )
        )

    if not args.apply:
        for name, url, body in writes:
            print("DRY-RUN would POST %s %s" % (name, json.dumps(body)))
        print("DRY-RUN nothing was written. Re-run with --apply to write.")
        return 0

    failed = False
    for name, url, body in writes:
        try:
            status, resp = _request(url, key, method="POST", body=body)
        except urllib.error.HTTPError as exc:
            print("WRITE %-8s HTTP %s %s" % (name, exc.code, _redact(str(exc.reason), key)))
            failed = True
            continue
        ok = bool(resp.get("is_success"))
        print(
            "WRITE %-8s http=%s is_success=%s code=%s msg=%s"
            % (name, status, ok, resp.get("response_code"), str(resp.get("message"))[:90])
        )
        if not ok:
            failed = True

    time.sleep(3)
    after_alarm = read_alarm(company, key, args.alarm_id, args.days)
    print("AFTER   %s" % json.dumps(describe(after_alarm) if after_alarm else {}))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
