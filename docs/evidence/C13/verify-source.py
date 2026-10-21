"""Reproduce the C13 source identity without changing the checkout."""
from pathlib import Path
import hashlib
import json
import subprocess

root = Path(__file__).resolve().parents[3]
paths = subprocess.check_output(['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard'], cwd=root).decode().split('\0')
excluded = {'SHA256SUMS.txt', 'plans/progress.json', 'docs/agents/SESSION_HANDOFF.json'}
digest = hashlib.sha256()
files = {}
for name in sorted(set(paths) - {''}):
    if name in excluded or name.startswith('docs/evidence/'):
        continue
    path = root / name
    if path.is_file():
        value = hashlib.sha256(path.read_bytes()).hexdigest()
        files[name] = value
        digest.update(name.encode() + b'\0' + bytes.fromhex(value))
identity = 'sha256:' + digest.hexdigest()
expected = json.loads((root / 'docs/evidence/C13/source-files.json').read_text())
assert expected == {'source_identity': identity, 'files': files}, 'Source identity/file inventory mismatch'
assert json.loads((root / 'docs/evidence/C13.json').read_text())['source_identity'] == identity
print(identity + '; ' + str(len(files)) + ' source files verified')
