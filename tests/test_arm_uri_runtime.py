"""Local ARM string-function model, not a live ARM deployment acceptance test."""
import json
from pathlib import Path
import re
import unittest
from urllib.parse import quote, urljoin

REPO = Path(__file__).resolve().parents[1]
FILES = ('azuredeploy.json', 'Playbooks/SOCRadar-Alarm-Import/azuredeploy.json',
         'Playbooks/SOCRadar-Alarm-Sync/azuredeploy.json')
RUNTIME_WORKSPACE = "@{parameters('WorkspaceId')}"
RUNTIME_INCIDENT = "@{items('For_Each_Incident')?['name']}"


def evaluate(expression, endpoint='https://api.loganalytics.io', management='https://management.azure.com'):
    """Only the string operations used in the shipped URI expressions are supported."""
    if not expression.startswith('['):
        return expression
    tokens = re.findall(r"'(?:[^']|'')*'|[A-Za-z_][A-Za-z_0-9]*|[().,]", expression[1:-1])
    pos = 0

    def parse():
        nonlocal pos
        token = tokens[pos]
        pos += 1
        if token.startswith("'"):
            result = token[1:-1].replace("''", "'")
        else:
            if tokens[pos] != '(':
                raise ValueError('expected function')
            pos += 1
            args = []
            while tokens[pos] != ')':
                args.append(parse())
                if tokens[pos] == ',':
                    pos += 1
                elif tokens[pos] != ')':
                    raise ValueError('expected comma')
            pos += 1
            functions = {
                'parameters': lambda key: {'LogAnalyticsQueryEndpoint': endpoint,
                    'WorkspaceResourceGroup': 'rg-synthetic', 'WorkspaceName': 'law-synthetic'}[key],
                'variables': lambda key: {'managementBaseUrl': management}[key],
                'subscription': lambda: {'subscriptionId': 'subscription-synthetic'},
                'format': lambda pattern, *values: pattern.format(*values),
                'createArray': lambda *values: list(values),
                'join': lambda values, separator: separator.join(values),
                'concat': lambda *values: ''.join(values),
                'string': lambda value: str(value),
                'uri': lambda base, relative: quote(urljoin(base, relative), safe=":/?#[]@!$&'()*+,;=%"),
            }
            if token not in functions:
                raise ValueError('unsupported function: ' + token)
            result = functions[token](*args)
        while pos < len(tokens) and tokens[pos] == '.':
            pos += 1
            result = result[tokens[pos]]
            pos += 1
        return result

    result = parse()
    if pos != len(tokens):
        raise ValueError('unconsumed expression')
    return result


def runtime_uris(value, path=''):
    if isinstance(value, dict):
        for key, child in value.items():
            if key == 'uri' and isinstance(child, str) and child.startswith('[') and '@{' in child:
                yield path + '/uri', child
            else:
                yield from runtime_uris(child, path + '/' + key)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from runtime_uris(child, path + '/' + str(index))


class RuntimeUriTests(unittest.TestCase):
    def test_model_encodes_runtime_braces_inside_uri(self):
        bad = "[uri(parameters('LogAnalyticsQueryEndpoint'), 'v1/workspaces/@{parameters(''WorkspaceId'')}/query')]"
        result = evaluate(bad)
        self.assertIn('@%7B', result)
        self.assertNotIn(RUNTIME_WORKSPACE, result)

    def test_shipped_runtime_uri_text_is_preserved(self):
        counts = []
        for name in FILES:
            values = list(runtime_uris(json.loads((REPO / name).read_text())))
            counts.append(len(values))
            for path, expression in values:
                for endpoint, management in (
                    ('https://api.loganalytics.io', 'https://management.azure.com'),
                    ('https://api.loganalytics.io/', 'https://management.azure.com/'),
                    ('https://api.loganalytics.azure.cn', 'https://management.chinacloudapi.cn'),
                ):
                    with self.subTest(file=name, path=path, endpoint=endpoint):
                        if 'WorkspaceId' in expression:
                            expected = endpoint.rstrip('/') + '/v1/workspaces/' + RUNTIME_WORKSPACE + '/query'
                        else:
                            suffix = '/entities?api-version=2023-11-01' if '/entities?' in expression else '?api-version=2023-11-01'
                            expected = management.rstrip('/') + '/subscriptions/subscription-synthetic/resourceGroups/rg-synthetic/providers/Microsoft.OperationalInsights/workspaces/law-synthetic/providers/Microsoft.SecurityInsights/incidents/' + RUNTIME_INCIDENT + suffix
                        self.assertEqual(evaluate(expression, endpoint, management), expected)
        self.assertEqual(counts, [5, 3, 2])

    def test_model_rejects_unsupported_functions(self):
        with self.assertRaises(ValueError):
            evaluate("[unknown('x')]")


if __name__ == '__main__':
    unittest.main()
