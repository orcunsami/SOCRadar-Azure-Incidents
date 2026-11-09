"""Contract checks must inspect constant ARM payloads, including deliberate breaks."""
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from arm_literals import arm_literals

assert arm_literals("[json('[]')]") == []
assert arm_literals("[string('a''b')]") == "a'b"
assert arm_literals({'customDetails': '[json(\'{"AlarmId":"AlarmId"}\')]'}) == {'customDetails': {'AlarmId': 'AlarmId'}}
assert arm_literals("[variables('unknown')]") == "[variables('unknown')]"
try:
    arm_literals("[json('broken')]")
except json.JSONDecodeError:
    pass
else:
    raise AssertionError('invalid constant silently accepted')
print('ARM literal decoding: 5 checks passed')
