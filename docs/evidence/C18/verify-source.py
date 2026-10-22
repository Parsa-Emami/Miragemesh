"""Verify C18's source identity, fixture inventory and completion evidence."""
import hashlib
import json
import re
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
evidence = root / "docs/evidence/C18"
expected = {"source_identity": identity, "files": files}
assert json.loads((evidence / "source-files.json").read_text()) == expected
proof = json.loads((root / "docs/evidence/C18.json").read_text())
assert proof["commit_id"] == "C18"
assert proof["source_identity"] == identity and proof["passed"] is True
assert proof["planning_template"] is False
assert proof["source_manifest"] == "docs/evidence/C18/source-files.json"
assert proof["commands"], "evidence must contain executed commands"
assert all(command["exit_code"] == 0 for command in proof["commands"])
assert all(command["source_identity"] == identity for command in proof["commands"])
for command in proof["commands"]:
    output = root / command["output_path"]
    assert output.is_file(), f"missing command log: {output}"
    assert hashlib.sha256(output.read_bytes()).hexdigest() == command["stored_output_sha256"]
recorded = [json.loads(line) for line in (evidence / "commands.jsonl").read_text().splitlines()]
assert recorded == proof["commands"], "evidence commands differ from commands.jsonl"
fixtures = {
    path: hashlib.sha256((root / path).read_bytes()).hexdigest()
    for path in sorted(proof["fixtures"]["sha256"])
}
assert fixtures == proof["fixtures"]["sha256"]
network_calls = re.compile(rb"\b(socket|connect|accept|accept4|bind|listen|sendto|recvfrom|sendmsg|recvmsg)\(")
assert not network_calls.findall((evidence / "network.trace").read_bytes())
progress = json.loads((root / "plans/progress.json").read_text())
state = next(task for task in progress["commits"] if task["id"] == "C18")
assert state["status"] == "verified" and state["source_identity"] == identity
assert state["evidence"] == ["docs/evidence/C18.json"]
project_state = json.loads((root / "plans/project-state.json").read_text())
assert project_state["next_task"] == "C19"
web = json.loads((root / "apps/web/src/generated/project.json").read_text())
web_state = next(task for task in web["tasks"] if task["id"] == "C18")
assert web_state["status"] == "verified"
head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
assert proof["delivery"]["push_performed"] is False
assert proof["delivery"]["publication_performed"] is False
if proof["delivery"]["commit_created"]:
    feature_commit = proof["delivery"]["commit"]
    subprocess.run(["git", "merge-base", "--is-ancestor", feature_commit, head], cwd=root, check=True)
else:
    assert "commit" not in proof["delivery"]
assert proof["remote_actions_executed"] is False
print(f"{identity}; {len(files)} source files, {len(proof['commands'])} commands verified")
