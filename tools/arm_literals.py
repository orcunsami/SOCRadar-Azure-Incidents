"""Decode literal ARM json()/string() values for deployment contract checks."""
import json
import re


def arm_literals(value):
    if isinstance(value, dict):
        return {key: arm_literals(child) for key, child in value.items()}
    if isinstance(value, list):
        return [arm_literals(child) for child in value]
    if isinstance(value, str):
        match = re.fullmatch(r"\[(json|string)\('((?:[^']|'')*)'\)\]", value, re.DOTALL)
        if match:
            literal = match[2].replace("''", "'")
            return arm_literals(json.loads(literal)) if match[1] == 'json' else literal
    return value
