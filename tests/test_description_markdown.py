#!/usr/bin/env python3
"""Pin the markdown-safe incident description.

The Microsoft Sentinel incident page renders the description as markdown. The old
content block joined fields with ' -*- ', which the page turned into italics and dashes,
and alarm text with '*', '_', '`' or '<' lost characters the same way.

  - Content is a field/value table built from the real keys of the alarm content.
    Content that is not an object (a string, number, list) goes into a code block.
  - Words in the alarm text are escaped, URL words are left alone (an escape inside a
    link shows up as a literal backslash).
  - Escaping makes text longer, so the caps are applied after it: details 1500, table
    2600, cell 300, and the whole description is cut at 5000. Microsoft Sentinel rejects
    a longer description, the alarm loop fails and the checkpoint stops moving.

The checks pin exact expressions, not just that a word appears somewhere, and the import
actions must be identical in the root template and the standalone playbook.

Run:  python3 tests/test_description_markdown.py
"""

import json
import os

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATES = [os.path.join(REPO, "azuredeploy.json"),
             os.path.join(REPO, "Playbooks", "SOCRadar-Alarm-Import", "azuredeploy.json")]

A = "items('For_Each_Alarm')"
EMPTYC = (f"or(equals(string(coalesce({A}?['content'], '')), ''), "
          f"equals(string(coalesce({A}?['content'], '')), '{{}}'))")
FULL = [("'*'", "'\\*'"), ("'_'", "'\\_'"), ("'`'", "'\\`'"), ("'~'", "'\\~'"), ("'['", "'\\['"),
        ("']'", "'\\]'"), ("'<'", "'&lt;'"), ("'>'", "'&gt;'"), ("'|'", "'\\|'")]
# The cell expression repeats its value three times (value, length check, substring);
# the minimal escapes run on every branch, the full set only on plain text.
ROW_COUNT = {"'<', '&lt;'": 12, "'>', '&gt;'": 12, "'|', '\\|'": 12}

failures = []
checks = 0


def check(condition, message):
    global checks
    checks += 1
    if not condition:
        failures.append(message)


def find(o, name):
    if isinstance(o, dict):
        for k, v in o.items():
            if k == name and isinstance(v, dict) and "type" in v:
                return v
            r = find(v, name)
            if r is not None:
                return r
    elif isinstance(o, list):
        for v in o:
            r = find(v, name)
            if r is not None:
                return r


copies = []
for path in TEMPLATES:
    name = os.path.relpath(path, REPO)
    t = json.load(open(path, encoding="utf-8"))
    acts = find(t, "Check_If_Open_Status")["actions"]
    copies.append(json.dumps(acts, sort_keys=True))
    create = acts["Create_New_Incident"]
    desc = create["inputs"]["body"]["description"]

    check("-*-" not in json.dumps(t), f"{name}: ' -*- ' separator is back")
    check(desc.startswith("@{take(concat(") and desc.endswith(", 5000)}"), f"{name}: description is not cut at 5000")
    check("outputs('Details_Markdown')" in desc and "outputs('Content_Markdown')" in desc,
          f"{name}: description does not use the markdown outputs")
    check("['alarm_text']" not in desc and "['content']" not in desc, f"{name}: description reads raw alarm fields")
    check(create["runAfter"] == {"Details_Markdown": ["Succeeded"]}, f"{name}: incident does not wait for the description")

    words = acts.get("Select_Detail_Words", {}).get("inputs", {})
    sel = words.get("select", "")
    check(words.get("from") == f"@split(replace(take(coalesce({A}?['alarm_text'], ''), 1500), decodeUriComponent('%0A'), ' '), ' ')",
          f"{name}: alarm text is not split into words")
    check(sel.startswith("@if(contains(item(), '://'), item(), "), f"{name}: URL words are escaped")
    for a, b in FULL:
        check(sel.count(f"{a}, {b}") == 1, f"{name}: alarm text escape {a} -> {b} missing or changed")

    det = acts.get("Details_Markdown", {}).get("inputs", "")
    check(det.startswith("@concat(take(join(body('Select_Detail_Words'), ' '), 1500), "), f"{name}: details not capped after escaping")
    check(det.endswith(", '...', ''))"), f"{name}: details lost the truncation marker")

    fc = acts.get("Format_Content", {}).get("actions", {})
    rows = fc.get("Select_Content_Rows", {}).get("inputs", {})
    rsel = rows.get("select", "")
    check(rows.get("from") == "@union(body('Select_Content_Keys'), body('Select_Content_Keys'))",
          f"{name}: repeated array keys are not deduplicated")
    for a, b in FULL:
        want = ROW_COUNT.get(f"{a}, {b}", 3)
        check(rsel.count(f"{a}, {b}") == want, f"{name}: cell escape {a} -> {b} expected {want}x")
    check(rsel.count("), 300), concat(substring(") == 1 and rsel.count(", 0, 300), '...')") == 1,
          f"{name}: cell cap 300 missing or changed")
    check(fc.get("Content_Table", {}).get("inputs", "").endswith(", 2600))"), f"{name}: table cap 2600 missing or changed")
    check(EMPTYC in fc.get("Content_Nodes", {}).get("inputs", ""), f"{name}: content nodes do not guard empty content")

    md = acts.get("Content_Markdown", {})
    mdi = md.get("inputs", "")
    check(set(md.get("runAfter", {}).get("Format_Content", [])) == {"Succeeded", "Failed", "TimedOut", "Skipped"},
          f"{name}: a failed table build can stop the incident")
    check(f"or(not(empty(outputs('Content_Table'))), {EMPTYC})" in mdi,
          f"{name}: non-object content is not routed to the code block")
    check(f"take(string({A}?['content']), 2000)" in mdi and mdi.count("```") == 2, f"{name}: code block fallback missing or uncapped")

check(len(copies) == 2 and copies[0] == copies[1], "root and playbook import actions differ")

if failures:
    for f in failures:
        print("FAIL", f)
    raise SystemExit(1)
print(f"Markdown-safe description verified in {checks} assertions.")
