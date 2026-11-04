#!/usr/bin/env python3
"""Break the lookback bounds on purpose and prove tests/test_lookback_bounds.py notices.

Each mutation is applied to one copy of the tree and the test is run; a mutation that survives is
BLIND and the run exits non-zero.

    python3 tests/mutate_lookback_bounds.py
"""
import os
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FILES = ["azuredeploy.json", os.path.join("Playbooks", "SOCRadar-Alarm-Import", "azuredeploy.json")]
TEST = os.path.join("tests", "test_lookback_bounds.py")

MUTATIONS = []
for f in FILES:
    MUTATIONS += [
        (f"{f}: maxValue 21600", f, '"maxValue": 10080', '"maxValue": 21600'),
        (f"{f}: minValue 1", f, '"minValue": 10,', '"minValue": 1,'),
        (f"{f}: the window clamp moves", f, ", 10080))", ", 21600))"),
    ]

blind = 0
for label, rel, old, new in MUTATIONS:
    with tempfile.TemporaryDirectory() as tmp:
        work = os.path.join(tmp, "repo")
        shutil.copytree(REPO, work, ignore=shutil.ignore_patterns(".git", "__pycache__"))
        path = os.path.join(work, rel)
        text = open(path, encoding="utf-8").read()
        if old not in text:
            print(f"  STALE {label}: pattern not found")
            blind += 1
            continue
        open(path, "w", encoding="utf-8").write(text.replace(old, new, 1))
        try:
            result = subprocess.run([sys.executable, TEST], cwd=work, capture_output=True, text=True, timeout=60)
            code = result.returncode
            # Only the test's own "FAIL:" lines count as caught: a traceback also exits non-zero.
            banner = code == 1 and result.stdout.startswith("FAIL:")
        except subprocess.TimeoutExpired:
            code, banner = 124, False
        if code == 0:
            print(f"  BLIND {label}")
            blind += 1
        elif not banner:
            print(f"  CRASH {label}: the test died (rc {code}) without its FAIL line")
            blind += 1
        else:
            print(f"  caught {label}")
print(f"blind or stale: {blind} of {len(MUTATIONS)}")
sys.exit(1 if blind else 0)
