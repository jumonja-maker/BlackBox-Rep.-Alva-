"""QA-only undefined-binding gate backed by Pyflakes, never a runtime dependency.

Usage: python tools/check_undefined_names.py [paths ...] [--report result.json]
The gate deliberately excludes unused imports/locals. Syntax errors, undefined
names/locals/exports and malformed annotations fail; missing QA tooling or input
is INCOMPLETE (exit 2), never an apparent PASS.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PATHS = ('src', 'blackbox_universal', 'tools', 'tests', 'app.py', 'maintenance_entry.py')


def check_paths(paths):
    try:
        from pyflakes import api, messages
    except ImportError:
        return {'status':'INCOMPLETE', 'filesChecked':0, 'findings':[],
                'error':'QA dependency pyflakes is required; install the pinned tooling requirements'}, 2
    selected = (messages.UndefinedName, messages.UndefinedLocal, messages.UndefinedExport,
                messages.ForwardAnnotationSyntaxError)
    findings = []
    class Reporter:
        def flake(self, message):
            if isinstance(message, selected):
                findings.append({'path':message.filename, 'line':message.lineno,
                    'column':message.col+1, 'code':type(message).__name__,
                    'message':message.message % message.message_args})
        def syntaxError(self, filename, message, lineno, offset, text):
            findings.append({'path':filename, 'line':lineno or 0, 'column':offset or 0,
                             'code':'SyntaxError', 'message':message})
        def unexpectedError(self, filename, message):
            findings.append({'path':filename, 'line':0, 'column':0,
                             'code':'InspectionError', 'message':message})
    files = set()
    for value in paths:
        path = Path(value)
        if not path.exists():
            return {'status':'INCOMPLETE', 'filesChecked':0, 'findings':[],
                    'error':'Required source path does not exist: '+str(path)}, 2
        if path.is_dir():
            files.update(p for p in path.rglob('*.py') if p.is_file())
        elif path.suffix == '.py':
            files.add(path)
        else:
            return {'status':'INCOMPLETE', 'filesChecked':0, 'findings':[],
                    'error':'Expected a Python source file or directory: '+str(path)}, 2
    if not files:
        return {'status':'INCOMPLETE', 'filesChecked':0, 'findings':[],
                'error':'No Python source files selected'}, 2
    reporter = Reporter()
    for path in sorted(files, key=str):
        api.checkPath(str(path), reporter=reporter)
    findings.sort(key=lambda f:(f['path'], f['line'], f['column'], f['code']))
    return {'status':'FAIL' if findings else 'PASS', 'filesChecked':len(files),
            'findings':findings}, 1 if findings else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('paths', nargs='*', type=Path)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args(argv)
    paths = args.paths or [ROOT/path for path in DEFAULT_PATHS]
    result, code = check_paths(paths)
    encoded = json.dumps(result, ensure_ascii=False, indent=2)+'\n'
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(encoded, encoding='utf-8')
    print(encoded, end='')
    return code


if __name__ == '__main__':
    raise SystemExit(main())
