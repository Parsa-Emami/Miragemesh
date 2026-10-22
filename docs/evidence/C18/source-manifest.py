"""Write C18's exact source manifest and identity digest."""
import hashlib
import json
import subprocess
from pathlib import Path

root = Path(__file__).resolve().parents[3]
paths = subprocess.check_output(
    ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=root
).decode().split("\0")
excluded = {"SHA256SUMS.txt", "plans/progress.json", "docs/agents/SESSION_HANDOFF.json"}
files = {}
digest = hashlib.sha256()
for name in sorted(set(paths) - {""}):
    if name in excluded or name.startswith("docs/evidence/"):
        continue
    path = root / name
    if path.is_file():
        value = hashlib.sha256(path.read_bytes()).hexdigest()
        files[name] = value
        digest.update(name.encode() + b"\0" + bytes.fromhex(value))
output = root / "docs/evidence/C18/source-files.json"
output.write_text(json.dumps({"source_identity": "sha256:" + digest.hexdigest(), "files": files}, indent=2) + "\n")
print("sha256:" + digest.hexdigest())
