#!/usr/bin/env python3
"""Report what severities real SOCRadar alarms actually carry.

The analytic rules in this repo filter on alarm_risk_level. That filter is only
meaningful if the values it looks for exist in the feed. This script answers that
question directly against the API, without deploying anything to Azure.

Reads SOCRADAR_API_KEY and SOCRADAR_COMPANY_ID from the environment. The key is
never passed on a command line and never printed, including in tracebacks.

Usage:
    export SOCRADAR_API_KEY=...        # or put it in a .env this script sources
    export SOCRADAR_COMPANY_ID=...
    python3 check_alarm_severity.py [--days 30] [--out severity.json]
"""

import argparse
import collections
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = "https://platform.socradar.com/api/company/{company}/incidents/v4"
PAGE_LIMIT = 100
MAX_PAGES = 200


def _redact(text, secret):
    """Keep the key out of any string we are about to print."""
    if secret and secret in text:
        text = text.replace(secret, "***REDACTED***")
    return text


def fetch_page(company, key, page, start_epoch):
    query = urllib.parse.urlencode(
        {
            "page": page,
            "limit": PAGE_LIMIT,
            "start_date": start_epoch,
            "include_total_records": "true",
        }
    )
    url = BASE.format(company=company) + "?" + query
    req = urllib.request.Request(url, headers={"API-Key": key})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode("utf-8"))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--days", type=int, default=30)
    parser.add_argument("--out", default="severity.json")
    args = parser.parse_args()

    key = os.environ.get("SOCRADAR_API_KEY")
    company = os.environ.get("SOCRADAR_COMPANY_ID")
    if not key or not company:
        print("SOCRADAR_API_KEY and SOCRADAR_COMPANY_ID must be set", file=sys.stderr)
        return 2

    start_epoch = int(time.time()) - args.days * 86400

    severity = collections.Counter()
    status = collections.Counter()
    main_type = collections.Counter()
    closed = collections.Counter()
    total_records = None
    pages_read = 0
    alarms = 0
    largest = {"alarm_id": None, "bytes": 0}

    try:
        for page in range(1, MAX_PAGES + 1):
            body = fetch_page(company, key, page, start_epoch)
            # The API wraps the list: {"data": {"alarms": [...], "total_records": N}}
            data = body.get("data") or {}
            if total_records is None:
                total_records = data.get("total_records")
            batch = data.get("alarms") or []
            if not batch:
                break
            pages_read += 1
            for alarm in batch:
                alarms += 1
                severity[str(alarm.get("alarm_risk_level"))] += 1
                status[str(alarm.get("status"))] += 1
                main_type[str(alarm.get("alarm_main_type"))] += 1
                closed[str(alarm.get("is_closed"))] += 1
                size = len(json.dumps(alarm))
                if size > largest["bytes"]:
                    largest = {"alarm_id": alarm.get("alarm_id"), "bytes": size}
            if len(batch) < PAGE_LIMIT:
                break
    except urllib.error.HTTPError as exc:
        print(_redact(f"HTTP {exc.code} on page {page}", key), file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001 - we must redact before surfacing
        print(_redact(f"{type(exc).__name__}: {exc}", key), file=sys.stderr)
        return 1

    report = {
        "window_days": args.days,
        "total_records_reported": total_records,
        "alarms_read": alarms,
        "pages_read": pages_read,
        "severity": dict(severity.most_common()),
        "status": dict(status.most_common()),
        "main_type": dict(main_type.most_common()),
        "is_closed": dict(closed.most_common()),
        "largest_alarm": largest,
    }
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)

    print(f"window            : last {args.days} days")
    print(f"total_records     : {total_records}")
    print(f"alarms read       : {alarms} over {pages_read} page(s)")
    print(f"largest alarm     : {largest['bytes']} bytes (id {largest['alarm_id']})")
    print("\nalarm_risk_level:")
    for value, count in severity.most_common():
        share = 100.0 * count / alarms if alarms else 0
        print(f"  {value:<12} {count:>6}  {share:5.1f}%")
    print("\nstatus:")
    for value, count in status.most_common():
        print(f"  {value:<12} {count:>6}")
    print(f"\nwrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
