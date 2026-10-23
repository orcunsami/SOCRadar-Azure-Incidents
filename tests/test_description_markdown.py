#!/usr/bin/env python3
"""Pin the markdown-safe incident description.

The Microsoft Sentinel incident page renders the description as markdown. The old
content block joined fields with ' -*- ', which the page turned into italics and dashes,
and alarm text with '*', '_', '`' or '<' lost characters the same way.

  - Content is a field/value table built from the real keys of the alarm content.
  - Words in the alarm text are escaped, URL words are left alone (an escape inside a
    link shows up as a literal backslash).
  - If the table cannot be built, the content falls back to a code block, never to
    nothing and never to a failed incident.

Run:  python3 tests/test_description_markdown.py
"""

import json
import os

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATES = [os.path.join(REPO, "azuredeploy.json"),
             os.path.join(REPO, "Playbooks", "SOCRadar-Alarm-Import", "azuredeploy.json")]

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
            if k == name:
                return v
            r = find(v, name)
            if r is not None:
                return r
    elif isinstance(o, list):
        for v in o:
            r = find(v, name)
            if r is not None:
                return r


for path in TEMPLATES:
    name = os.path.relpath(path, REPO)
    t = json.load(open(path, encoding="utf-8"))
    acts = find(t, "Check_If_Open_Status")["actions"]
    create = acts["Create_New_Incident"]
    desc = create["inputs"]["body"]["description"]

    check("-*-" not in json.dumps(t), f"{name}: ' -*- ' separator is back")
    check("outputs('Details_Markdown')" in desc, f"{name}: description does not use Details_Markdown")
    check("outputs('Content_Markdown')" in desc, f"{name}: description does not use Content_Markdown")
    check("['alarm_text']" not in desc, f"{name}: description reads raw alarm_text")
    check("['content']" not in desc, f"{name}: description reads raw content")
    check(create["runAfter"] == {"Details_Markdown": ["Succeeded"]}, f"{name}: incident does not wait for the description")

    words = acts.get("Select_Detail_Words", {}).get("inputs", {}).get("select", "")
    for ch in ["'*'", "'_'", "'`'", "'['", "'<'"]:
        check(ch in words, f"{name}: alarm text does not escape {ch}")
    check("contains(item(), '://')" in words, f"{name}: URL words are escaped")

    rows = acts.get("Format_Content", {}).get("actions", {}).get("Select_Content_Rows", {}).get("inputs", {})
    check("union(" in rows.get("from", ""), f"{name}: repeated array keys are not deduplicated")
    check("'\\|'" in rows.get("select", ""), f"{name}: '|' in a value is not escaped")

    md = acts.get("Content_Markdown", {})
    check(set(md.get("runAfter", {}).get("Format_Content", [])) >= {"Succeeded", "Failed"},
          f"{name}: a failed table build stops the incident")
    check("```" in md.get("inputs", ""), f"{name}: no code block fallback")

if failures:
    for f in failures:
        print("FAIL", f)
    raise SystemExit(1)
print(f"Markdown-safe description verified in {checks} assertions.")
