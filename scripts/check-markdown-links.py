#!/usr/bin/env python3
"""Check repository-local inline Markdown links without network access."""
import pathlib
import re
import sys
import urllib.parse

root = pathlib.Path(__file__).resolve().parent.parent
errors = []
files = [*root.glob('*.md'), *root.joinpath('docs').rglob('*.md'), *root.joinpath('tasks').rglob('*.md')]
for source in files:
    body = re.sub(r'```.*?```', '', source.read_text(), flags=re.S)
    for raw in re.findall(r'!?\[[^\]]*\]\(([^)]+)\)', body):
        target = raw.strip().split(' "', 1)[0].strip('<>')
        parsed = urllib.parse.urlsplit(target)
        if parsed.scheme or parsed.netloc or not parsed.path:
            continue
        path = pathlib.Path(urllib.parse.unquote(parsed.path))
        resolved = (root / str(path).lstrip('/')) if path.is_absolute() else source.parent / path
        if not resolved.exists():
            errors.append(f'{source.relative_to(root)}: missing link target {target}')
if errors:
    print('\n'.join(errors), file=sys.stderr)
    sys.exit(1)
print(f'local Markdown links ok ({len(files)} files)')
