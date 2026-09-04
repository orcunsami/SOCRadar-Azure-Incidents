#!/usr/bin/env python3
"""Fail on malformed ARM and Logic App expressions.

Nothing else in this repo reads an expression. `az deployment group validate` parses the
template as JSON and checks resource shapes; it never evaluates a workflow action's
expression, so a broken one deploys cleanly and fails on the first run. The drift check
compares the two copies of the same expression against each other, so an identical
mistake made in both copies passes it.

That happened on 2026-09-04: adding a fourth label to Build_Labels left an empty argument
in the concat call (`..., ''), , if(...`). The template validated, the drift check was
clean, every test passed, and the import would have failed at run time on the first alarm.

Two checks, both on the expression text with single-quoted literals removed:
  - no empty function argument: `(,`  `,,`  `,)`
  - balanced parentheses, for strings that are a single expression end to end

Run:  python3 tools/check_expressions.py
"""

import json
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATES = [os.path.join(REPO, "azuredeploy.json")] + [
    os.path.join(REPO, "Playbooks", name, "azuredeploy.json")
    for name in sorted(os.listdir(os.path.join(REPO, "Playbooks")))
    if os.path.isfile(os.path.join(REPO, "Playbooks", name, "azuredeploy.json"))
]


def strip_literals(text):
    """Blank out every single-quoted literal, keeping the string's length and structure.

    Both expression languages escape a quote inside a literal by doubling it.
    """
    out = []
    index = 0
    while index < len(text):
        char = text[index]
        if char != "'":
            out.append(char)
            index += 1
            continue
        index += 1
        while index < len(text):
            if text[index] == "'":
                if index + 1 < len(text) and text[index + 1] == "'":
                    index += 2
                    continue
                index += 1
                break
            index += 1
        out.append("''")
    return "".join(out)


def is_expression(text):
    """Strings the platform evaluates rather than takes literally."""
    if text.startswith("[") and text.endswith("]") and not text.startswith("[["):
        return True                      # ARM template expression
    if text.startswith("@") and not text.startswith("@@"):
        return True                      # Logic App expression
    return "@{" in text                  # Logic App string interpolation


def single_expression(text):
    """True when the whole string is one expression, so its parentheses must balance."""
    if text.startswith("[") and text.endswith("]") and not text.startswith("[["):
        return True
    return text.startswith("@") and not text.startswith("@@") and "@{" not in text


def walk(node, path="$"):
    if isinstance(node, dict):
        for key, value in node.items():
            yield from walk(value, f"{path}.{key}")
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from walk(value, f"{path}[{index}]")
    elif isinstance(node, str):
        yield path, node


failures = []
checked = 0

for path in TEMPLATES:
    rel = os.path.relpath(path, REPO)
    with open(path, encoding="utf-8") as fh:
        template = json.load(fh)
    for location, text in walk(template):
        if not is_expression(text):
            continue
        checked += 1
        bare = strip_literals(text)

        for match in re.finditer(r"(\(\s*,|,\s*,|,\s*\))", bare):
            failures.append(f"{rel}: empty function argument at {location}: "
                            f"...{text[max(0, match.start() - 60):match.start() + 60]}...")

        if single_expression(text):
            depth = 0
            for char in bare:
                if char == "(":
                    depth += 1
                elif char == ")":
                    depth -= 1
                    if depth < 0:
                        break
            if depth != 0:
                failures.append(f"{rel}: unbalanced parentheses at {location}: {text[:120]}...")

if checked < 200:
    failures.append(f"only {checked} expressions were checked - this check has gone blind")

if failures:
    print("EXPRESSION CHECK FAILED\n")
    for item in failures:
        print("  - " + item)
    print(f"\n{len(failures)} problem(s).")
    sys.exit(1)

print(f"{checked} expressions parse: no empty arguments, parentheses balanced.")
