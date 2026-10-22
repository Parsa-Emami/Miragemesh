"""Verify C19 source identity, command logs, fixtures and progress binding."""
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
identity = "sha256:" + digest.hexdigest()
proof = json.loads((root / "docs/evidence/C19.json").read_text())
assert proof["commit_id"] == "C19" and proof["passed"] and not proof["planning_template"]
assert proof["source_identity"] == identity
assert json.loads((root / "docs/evidence/C19/source-files.json").read_text()) == {
    "source_identity": identity, "files": files
}
for command in proof["commands"]:
    assert command["exit_code"] == 0 and command["source_identity"] == identity
    output = root / command["output_path"]
    assert output.is_file()
    assert hashlib.sha256(output.read_bytes()).hexdigest() == command["stored_output_sha256"]
for name, expected in proof["fixtures"]["sha256"].items():
    assert hashlib.sha256((root / name).read_bytes()).hexdigest() == expected
progress = json.loads((root / "plans/progress.json").read_text())
state = next(item for item in progress["commits"] if item["id"] == "C19")
assert state["status"] == "verified" and state["source_identity"] == identity
assert state["evidence"] == ["docs/evidence/C19.json"]
head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
assert proof["implementation_commit"] in subprocess.check_output(
    ["git", "rev-list", head], cwd=root, text=True
).splitlines()
print(f"{identity}; {len(files)} source files, {len(proof['commands'])} command logs verified")
