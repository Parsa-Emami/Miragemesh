"""Verify C20 source identity, command logs, fixtures and progress binding."""
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
manifest = json.loads((root / "docs/evidence/C20/source-files.json").read_text())
assert manifest == {"source_identity": identity, "files": files}
proof = json.loads((root / "docs/evidence/C20.json").read_text())
assert proof["commit_id"] == "C20" and proof["passed"] and not proof["planning_template"]
assert proof["source_identity"] == identity
assert proof["source_manifest"] == "docs/evidence/C20/source-files.json"
for command in proof["commands"]:
    assert command["exit_code"] == 0 and command["source_identity"] == identity
    output = root / command["output_path"]
    assert output.is_file(), command["output_path"]
    assert hashlib.sha256(output.read_bytes()).hexdigest() == command["stored_output_sha256"], command["output_path"]
for name, expected in proof["fixtures"]["sha256"].items():
    assert hashlib.sha256((root / name).read_bytes()).hexdigest() == expected, name
progress = json.loads((root / "plans/progress.json").read_text())
state = next(item for item in progress["commits"] if item["id"] == "C20")
assert state["status"] == "verified" and state["source_identity"] == identity
assert state["evidence"] == ["docs/evidence/C20.json"]
handoff = json.loads((root / "docs/agents/SESSION_HANDOFF.json").read_text())
assert handoff["last_task"] == "C20" and handoff["status"] == "verified"
assert handoff["source_identity"] == identity and handoff["evidence"] == "docs/evidence/C20.json"
if proof["implementation_commit"] is None:
    assert proof["delivery"]["commit_created"] is False
else:
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    assert proof["implementation_commit"] in subprocess.check_output(
        ["git", "rev-list", head], cwd=root, text=True
    ).splitlines()
print(f"{identity}; {len(files)} source files, {len(proof['commands'])} command logs, {len(proof['fixtures']['sha256'])} fixtures verified")
