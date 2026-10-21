"""Verify C15's source identity, fixture inventory and completion evidence."""
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
        file_hash = hashlib.sha256(path.read_bytes()).hexdigest()
        files[name] = file_hash
        digest.update(name.encode() + b"\0" + bytes.fromhex(file_hash))
identity = "sha256:" + digest.hexdigest()
evidence = root / "docs/evidence/C15"
expected = {"source_identity": identity, "files": files}
assert json.loads((evidence / "source-files.json").read_text()) == expected
proof = json.loads((root / "docs/evidence/C15.json").read_text())
assert proof["source_identity"] == identity and proof["passed"] is True
progress = json.loads((root / "plans/progress.json").read_text())
state = next(task for task in progress["commits"] if task["id"] == "C15")
assert state["status"] == "verified" and state["source_identity"] == identity
assert all(command["exit_code"] == 0 for command in proof["commands"])
print(f"{identity}; {len(files)} source files verified")
