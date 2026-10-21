#!/usr/bin/env python3
"""Stage the working tree in a temporary index and clone-verify it."""
import os
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[3]
handle, name = tempfile.mkstemp(prefix='miragemesh-c12-index-')
os.close(handle)
os.unlink(name)
environment = os.environ.copy()
environment['GIT_INDEX_FILE'] = name
try:
    subprocess.run(['git', 'read-tree', 'HEAD'], cwd=root, env=environment, check=True)
    subprocess.run(['git', 'add', '-A'], cwd=root, env=environment, check=True)
    subprocess.run(['git', 'diff', '--cached', '--check'], cwd=root, env=environment, check=True)
    staged = subprocess.check_output(['git', 'diff', '--cached', '--stat'], cwd=root, env=environment, text=True)
    (root / 'docs/evidence/C13/candidate-diff-stat.log').write_text(staged)
    result = subprocess.run(['npm', 'run', 'test:clone'], cwd=root, env=environment)
    raise SystemExit(result.returncode)
finally:
    for suffix in ['', '.lock']:
        try:
            os.unlink(name + suffix)
        except FileNotFoundError:
            pass
