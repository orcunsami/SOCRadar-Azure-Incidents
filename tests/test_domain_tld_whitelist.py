#!/usr/bin/env python3
"""Domain entities are extracted with a real TLD whitelist, not a two-letter catch-all.

Why this test exists: the IoC regex used to end its alternation with a bare
``[a-z]{2}`` branch, which treats *any* two-letter suffix as a country-code TLD.
Only 248 of the 676 possible two-letter suffixes are real ccTLDs, so the rest turned
stealer-log name fragments into DNS entities -- ``reichardjamie.jr``,
``darrinpurcell.dp``, ``jtaylor594.jt``. Measured on 300 live alarms that branch
produced 260 junk entities and was the sole source of them.

The whitelist is checked against a pinned copy of the IANA list rather than a
hand-typed one, so a typo or a silent truncation fails here instead of shipping.

What this test deliberately does NOT do: broaden the whitelist to the full IANA set.
That was measured too and it is worse -- IANA carries ~1200 brand gTLDs that collide
with English surnames (``.schmidt``, ``.green``, ``.rogers``), which would add 157
more junk entities. The curated gTLD list stays curated on purpose.

Behaviour is asserted with Python's ``re``. That is a proxy for Kusto's RE2, and the
two were measured to agree on this regex before the change was made -- see
progress/task_azure_0070/kusto_re2_check.py.
"""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
TEMPLATES = ["azuredeploy.json", "Playbooks/SOCRadar-Alarm-Import/azuredeploy.json"]
# Pinned inside the repo so the gate runs in CI, where only this repo is checked out.
# Source: https://data.iana.org/TLD/tlds-alpha-by-domain.txt, Version 2026091400.
CCTLD_FILE = os.path.join(HERE, "iana-cctld-2letter.txt")

# Both KQL queries that extract domains. Naming them keeps the count honest: if a
# third extraction site appears, the count assert below fails.
EXPECTED_QUERIES = 2

DOMS_RX = re.compile(r"extend Doms0 = extract_all\(@'(.*?)', tolower\(nourl\)\)")
# The alternation after the label-repeat group, e.g. "(?:ac|ad|...|com|net|...)"
ALTERNATION_RX = re.compile(r"\(\?:\[a-z0-9\]\[a-z0-9-\]\{0,62\}\\\.\)\+\(\?:([^)]*)\)")

MUST_MATCH = [
    "evil-domain.com",              # plain gTLD
    "login.microsoftonline.com",    # multi-label
    "x.co.uk",                      # two-letter ccTLD, two levels
    "phish.xyz",                    # curated new gTLD
    "c2.ru",                        # two-letter ccTLD
    "bad.tr",                       # two-letter ccTLD
]
MUST_NOT_MATCH = [
    "reichardjamie.jr",             # name + "Junior", the measured top offender
    "darrinpurcell.dp",             # name + initials
    "jtaylor594.jt",                # name + initials
    "config.db",                    # file suffix that is not a ccTLD
    "model.rb",                     # source file
    "main.go",                      # source file
    "000005.ldb",                   # stealer-log artifact
    "messages.create",              # code symbol
]

failures = []


def check(cond, msg):
    if not cond:
        failures.append(msg)


def domain_regexes(path):
    """Every Doms0 regex in a template, un-escaped from its JSON string."""
    blob = json.dumps(json.load(open(path, encoding="utf-8")), ensure_ascii=False)
    return [m.replace("\\\\", "\\") for m in DOMS_RX.findall(blob)]


def load_cctlds():
    if not os.path.exists(CCTLD_FILE):
        failures.append(f"pinned IANA ccTLD list is missing: {CCTLD_FILE}")
        return None
    entries = open(CCTLD_FILE, encoding="utf-8").read().split()
    bad = [e for e in entries if not re.fullmatch(r"[a-z]{2}", e)]
    if bad:
        failures.append(f"pinned list has non-ccTLD entries: {bad[:5]}")
        return None
    return sorted(set(entries))


def main():
    os.chdir(REPO)
    cctlds = load_cctlds()
    seen = {}

    for path in TEMPLATES:
        regexes = domain_regexes(path)
        check(len(regexes) == EXPECTED_QUERIES,
              f"{path}: expected {EXPECTED_QUERIES} domain extractions, found {len(regexes)}")
        if not regexes:
            continue
        check(len(set(regexes)) == 1,
              f"{path}: its {len(regexes)} domain regexes disagree with each other")
        seen[path] = regexes[0]

        for rx in regexes:
            check("[a-z]{2}|" not in rx,
                  f"{path}: the two-letter catch-all [a-z]{{2}} is back in the whitelist")

            alt = ALTERNATION_RX.search(rx)
            if not alt:
                failures.append(f"{path}: could not read the TLD alternation out of the regex")
                continue
            branches = alt.group(1).split("|")
            two = sorted(b for b in branches if re.fullmatch(r"[a-z]{2}", b))
            if cctlds is not None:
                check(two == cctlds,
                      f"{path}: two-letter branches do not equal the pinned IANA ccTLD list "
                      f"(template {len(two)}, pinned {len(cctlds)}, "
                      f"missing {sorted(set(cctlds) - set(two))[:5]}, "
                      f"extra {sorted(set(two) - set(cctlds))[:5]})")
            check(len(branches) == len(set(branches)),
                  f"{path}: the TLD alternation repeats a branch")

    if len(set(seen.values())) > 1:
        failures.append("the templates carry different domain regexes: "
                        + ", ".join(sorted(seen)))

    # Behaviour, on the one regex the templates agree on.
    if seen:
        rx = re.compile(next(iter(seen.values())))
        for sample in MUST_MATCH:
            check(rx.findall(sample) == [sample],
                  f"real domain no longer extracted: {sample} -> {rx.findall(sample)}")
        for sample in MUST_NOT_MATCH:
            check(not rx.findall(sample),
                  f"junk extracted as a domain: {sample} -> {rx.findall(sample)}")

    for f in failures:
        print("FAIL " + f)
    checks = 2 * len(TEMPLATES) * EXPECTED_QUERIES + len(MUST_MATCH) + len(MUST_NOT_MATCH)
    print(f"{'FAIL' if failures else 'PASS'}  domain TLD whitelist  "
          f"({len(failures)} failure(s), ~{checks} checks)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
