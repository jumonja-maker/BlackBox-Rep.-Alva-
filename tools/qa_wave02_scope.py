"""Finite QA scope is tracked with the source, never inferred from missing code."""
import argparse
from pathlib import Path
import json
import os

SCOPES = {"r20": ["R20"], "r30": ["R20", "R30"],
          "r40": ["R20", "R40"], "full": ["R20", "R30", "R40", "R50"]}


def load_scope(requested=None):
    path = Path(__file__).with_suffix('.json')
    value = json.loads(path.read_text(encoding='utf-8'))
    if (type(value) is not dict or set(value) != {'schema', 'container', 'required_containers', 'endurance_required'}
            or value.get('schema') != 'blackbox.wave02.qa-scope/1'
            or value.get('container') not in SCOPES
            or value.get('required_containers') != SCOPES[value['container']]
            or value.get('endurance_required') is not (value['container'] == 'full')
            or requested is not None and requested != value['container']):
        raise ValueError('WAVE02_REQUIRED_SCOPE_MISMATCH')
    return value


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--container', choices=tuple(SCOPES))
    args = parser.parse_args()
    scope = load_scope(args.container)
    print(json.dumps(scope, sort_keys=True))
    if os.environ.get('GITHUB_OUTPUT'):
        with Path(os.environ['GITHUB_OUTPUT']).open('a', encoding='utf-8') as stream:
            stream.write('container=' + scope['container'] + '\n')
            stream.write('endurance_required=' + str(scope['endurance_required']).lower() + '\n')
