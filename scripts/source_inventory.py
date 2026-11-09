#!/usr/bin/env python3
"""Read-only source inventory; never imports or executes challenge files."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path


DEFAULT_EXCLUDES = {'.git', 'node_modules', '.venv', 'venv', '__pycache__',
                    '_skills_backup', '.pipcache'}
TEXT_SUFFIXES = {'.md', '.txt', '.log', '.py', '.sage', '.js', '.ts', '.c',
                 '.h', '.cpp', '.rs', '.go', '.php', '.json', '.yaml', '.yml'}


def inventory(root, excludes, output, hash_limit):
    files, skipped, errors = [], [], []

    def on_error(exc):
        errors.append({'path': str(exc.filename), 'error': str(exc)})

    for current, dirs, names in os.walk(root, followlinks=False, onerror=on_error):
        kept = []
        for name in sorted(dirs):
            path = Path(current) / name
            rel = path.relative_to(root).as_posix()
            linked = path.is_symlink() or getattr(path, 'is_junction', lambda: False)()
            if name.casefold() in DEFAULT_EXCLUDES or rel.casefold() in excludes or linked:
                skipped.append({'path': rel, 'reason': 'link' if linked else 'excluded'})
            else:
                kept.append(name)
        dirs[:] = kept
        for name in sorted(names):
            path = Path(current) / name
            rel = path.relative_to(root).as_posix()
            try:
                if path.is_symlink():
                    skipped.append({'path': rel, 'reason': 'link'})
                    continue
                if path.resolve() == output:
                    continue
                stat = path.stat()
                item = {'path': rel, 'size': stat.st_size, 'mtime_ns': stat.st_mtime_ns}
                if path.suffix.lower() in TEXT_SUFFIXES and stat.st_size <= hash_limit:
                    digest = hashlib.sha256()
                    with path.open('rb') as stream:
                        for block in iter(lambda: stream.read(1024 * 1024), b''):
                            digest.update(block)
                    after = path.stat()
                    if (after.st_size, after.st_mtime_ns) == (stat.st_size, stat.st_mtime_ns):
                        item['sha256'] = digest.hexdigest()
                    else:
                        item['unstable'] = True
                files.append(item)
            except OSError as exc:
                errors.append({'path': rel, 'error': str(exc)})
    return {'schema': 1, 'root': str(root),
            'generated_utc': datetime.now(timezone.utc).isoformat(),
            'excludes': sorted(DEFAULT_EXCLUDES | excludes), 'hash_limit': hash_limit,
            'files': sorted(files, key=lambda x: x['path']),
            'skipped': skipped, 'errors': errors}


def diff(previous, current):
    old = {x['path']: x for x in previous['files']}
    new = {x['path']: x for x in current['files']}
    changed = []
    for name in old.keys() & new.keys():
        a, b = old[name], new[name]
        if a.get('unstable') or b.get('unstable'):
            changed.append(name)
        elif 'sha256' in a and 'sha256' in b:
            if a['sha256'] != b['sha256']:
                changed.append(name)
        elif (a['size'], a['mtime_ns']) != (b['size'], b['mtime_ns']):
            changed.append(name)
    return {'added': sorted(new.keys() - old.keys()),
            'changed': sorted(changed), 'removed': sorted(old.keys() - new.keys())}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--previous', type=Path)
    parser.add_argument('--exclude', action='append', default=[],
                        help='Additional root-relative directory, repeatable')
    parser.add_argument('--hash-limit', type=int, default=2 * 1024 * 1024,
                        help='Hash recognized text files up to this size; other files get metadata')
    args = parser.parse_args()
    root, output = args.root.resolve(), args.output.resolve()
    if not root.is_dir() or args.hash_limit < 0:
        parser.error('root must be a directory and hash-limit must be nonnegative')
    excludes = {x.replace('\\', '/').strip('/').casefold() for x in args.exclude}
    previous = None
    if args.previous:
        if args.previous.resolve() == output:
            parser.error('previous and output must be distinct files')
        previous = json.loads(args.previous.read_text(encoding='utf-8-sig'))
        if Path(previous['root']).resolve() != root:
            parser.error('previous inventory belongs to a different root')
    report = inventory(root, excludes, output, args.hash_limit)
    if previous is not None:
        if previous.get('excludes') != report['excludes'] or previous.get('hash_limit') != report['hash_limit']:
            parser.error('use the same exclusions and hash-limit for comparable inventories')
        report['delta'] = diff(previous, report)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    groups = Counter(x['path'].split('/')[0] for x in report['files'])
    print(json.dumps({'files': len(report['files']), 'hashed': sum('sha256' in x for x in report['files']),
                      'groups': len(groups), 'skipped': len(report['skipped']),
                      'errors': len(report['errors']), 'output': str(output),
                      'delta': {k: len(v) for k, v in report.get('delta', {}).items()}}, ensure_ascii=False))
    return 1 if report['errors'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
