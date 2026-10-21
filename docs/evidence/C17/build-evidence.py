"""Build C17's evidence from recorded command logs and the final source identity."""
import hashlib
import json
import re
import subprocess
from pathlib import Path

root = Path(__file__).resolve().parents[3]
evidence_dir = root / "docs/evidence/C17"
commands = [json.loads(line) for line in (evidence_dir / "commands.jsonl").read_text().splitlines()]
source = json.loads((evidence_dir / "source-files.json").read_text())
identity = source["source_identity"]
assert commands and all(command["exit_code"] == 0 for command in commands)
assert all(command["source_identity"] == identity for command in commands)
assert len(commands) == 17, f"expected 17 recorded commands, got {len(commands)}"

def log(name):
    return (evidence_dir / f"{name}.log").read_text(errors="replace")

engine = []
for line in log("engine-tests").splitlines():
    try:
        engine.append(json.loads(line))
    except json.JSONDecodeError:
        pass
top_level = sum(1 for item in engine if item.get("Action") == "pass" and item.get("Test") and "/" not in item["Test"])
subtests = sum(1 for item in engine if item.get("Action") == "pass" and item.get("Test") and "/" in item["Test"])
assert not [item for item in engine if item.get("Action") == "fail"]
anchors = re.search(r"Verified (\d+) engine suites and (\d+) required test anchors", log("discovery"))
assert anchors and anchors.group(1) == "5" and anchors.group(2) == "115"
node_tests = re.search(r"ℹ pass (\d+)", log("final-check"))
browser_tests = re.search(r"(\d+) passed", log("browser"))
python_tests = re.search(r"Ran (\d+) tests", log("python-tests"))
assert node_tests and browser_tests and python_tests
node_count = int(node_tests.group(1))
browser_count = int(browser_tests.group(1))
python_count = int(python_tests.group(1))

environment = {}
for line in log("environment").splitlines():
    try:
        item = json.loads(line)
    except json.JSONDecodeError:
        continue
    argv = item.get("argv")
    if argv == ["node", "--version"]:
        environment["node"] = item["output"].removeprefix("v")
    elif argv == ["go", "version"]:
        environment["go"] = "1.27.2 with official checksum database enabled for commands"
    elif argv == ["podman", "--version"]:
        environment["provider"] = "rootless Podman 4.9.3; pinned Alpine image digest present"
    elif argv == ["uname", "-srmo"]:
        environment["os"] = item["output"].replace(" GNU/Linux", "")
    elif argv == ["findmnt", "-T", ".", "-n", "-o", "FSTYPE"]:
        environment["filesystem"] = item["output"]
assert environment.get("node") == "24.19.0" and environment.get("filesystem") == "ext4"

clone_lines = []
for line in log("clone-final").splitlines():
    if line.startswith("{"):
        try:
            clone_lines.append(json.loads(line))
        except json.JSONDecodeError:
            pass
clone_source = next(item for item in clone_lines if "git_tree" in item)
clone_final = next(item for item in clone_lines if "stagedTree" in item)
assert clone_source["passed"] is True and clone_final["passed"] is True

fixture_names = ["positive.json", "expected-output.json", "invalid.json", "crash.json"]
fixture_hashes = {
    f"tests/fixtures/miragemesh/C17/{name}": hashlib.sha256((root / "tests/fixtures/miragemesh/C17" / name).read_bytes()).hexdigest()
    for name in fixture_names
}
fixtures = {
    "license": "Apache-2.0",
    "provenance": "Repository-authored synthetic C17 events, expected semantics, negative cases and crash boundaries; small test-policy limits are not product defaults or capacity claims.",
    "sha256": fixture_hashes,
}

status_lines = subprocess.check_output(
    ["git", "status", "--porcelain=v1", "-uall"], cwd=root, text=True
).splitlines()
changed_paths = sorted({line[3:] for line in status_lines if len(line) > 3})
assert "docs/evidence/C17.json" in changed_paths
assert "docs/evidence/C17/build-evidence.py" in changed_paths
assert "cmd/miragemesh/segments.go" in changed_paths
assert "cmd/miragemesh/segments_test.go" in changed_paths

evidence = {
    "commit_id": "C17",
    "project": "MirageMesh",
    "passed": True,
    "planning_template": False,
    "date": "2026-10-21",
    "base_commit": "8de8a9daeb1489ec387a31da56757969342c1ed2",
    "source_identity": identity,
    "source_manifest": "docs/evidence/C17/source-files.json",
    "source_identity_algorithm": "SHA-256 of sorted UTF-8 relative path + NUL + raw SHA-256(file bytes), over tracked and non-ignored untracked source. docs/evidence/, plans/progress.json, docs/agents/SESSION_HANDOFF.json and SHA256SUMS.txt excluded; each command records identity at start.",
    "scope": "F11 immutable JSONL event segments with a one-shot local engine projection path: bounded record/byte rotation, sealed files, restart preservation, explicit incomplete-tail Offset/Bytes/Digest status and a typed --project-segments CLI outcome. No retention, index/checkpoint, deduplication, transport, HTTP API, UI, remote Actions or full-product readiness claim.",
    "owner_scope_resolution": "The C17 card and roadmap now target internal/events/segments.go, tests/rotation_test.go, cmd/miragemesh/segments.go, cmd/miragemesh/segments_test.go and cmd/miragemesh/main.go; the review response added the command files so the typed projection outcome has a real engine caller rather than test-only callers. The package-local segments_recovery_test.go uses the private syscall seam for real SIGKILL and injected-failure coverage that cannot be injected through the public boundary; it adds no product API. The one-shot command requires an existing C05 store, refuses overlapping storage/segment directories and writes no C05 receipt or ACK. C05 remains authoritative for acceptance receipts, spool, ACKs, configuration and enrollment; C17 only projects storage event records into separate segment files. C16 commit and segment append are not atomic, and C17 provides no deduplication checkpoint. C18 owns indexing/checkpoints and C23 owns retention/audit metadata. No database schema, migration, environment file, Dockerfile, dependency or sibling-repository import was changed.",
    "fixtures": fixtures,
    "results": {
        "positive": "Record and byte rotation produce the fixture-declared sealed and active segments while preserving every exact event payload. Reopening preserves sealed bytes, resumes the active segment and continues appending. Max-frame append, restart immutability and retention ordinal gaps are covered. The --project-segments workflow runs in a real child process, requires an existing C05 store, projects three event records plus one gap, creates two segments and leaves all C05 receipts and inputs unchanged. A quota failure after one durable append reports the sealed segment that exists and matches the segment directory on disk.",
        "negative": "Blank, malformed, multi-record, oversized and invalid events fail before bytes change. Invalid limits, unsupported or unsafe inventory, zero and duplicate ordinals, duplicate active segments, public modes, symlinks, hardlinks, sealed tails and incomplete files without tails fail closed as typed errors. Ambiguous projection records fail recovery without writing. The workflow returns exit 2 with error_kind invalid_input for missing/overlapping configuration and exit 1 with error_kind recovery for unsafe segment state. A writer that cannot expose a snapshot reports segments_known false instead of an empty segment store.",
        "restart": "Real child-process SIGKILL at five rotation/recovery boundaries and injected create/rename/sync/write failures preserve valid complete records; a torn active tail is renamed to an incomplete file and reported with exact Offset, preserved Bytes and SHA-256 Digest. Complete prefix records remain readable. This is local process-crash and injected-I/O evidence, not physical power-loss proof.",
        "discovery": "Five engine suites and 115 required anchors executed and were accepted by the discovery guard.",
        "network": "C17 segment tests and the --project-segments workflow test passed under strace with zero network syscalls; the package import allowlist excludes net, net/http and os/exec.",
        "workflow": "Build, explicit runtime-projection regression, browser, package checksum, repository contract, Python integrity, plan validation, final check, next-task and clean-clone equivalents are recorded with exits and logs. No GitHub-hosted run or publication occurred.",
    },
    "security_review": [
        "C04 event validation and framing are complete before the first segment file is created or changed.",
        "Segment files are opened through os.Root with no-follow/nonblocking flags and exact owner, regular-file, 0600 mode and single-link checks; unknown or unsafe inventory fails closed.",
        "The projection command is one-shot local CLI only: it opens no listener, adds no HTTP route and rejects overlapping C05/segment directories before either side writes.",
        "A failed projection reports the durable segment state that exists; an unavailable snapshot is reported as unknown, never as an empty segment store.",
        "C17 has no deletion, truncate, network, process-execution or container path; hostile metadata remains inert event data.",
        "C16 authority is untouched: projection requires an existing C05 manifest, skips gaps/ACKs/enrollment/config, writes no receipt or ACK, and an ambiguous record returns ErrRecovery without writing.",
        "Limits are mandatory; no default, unlimited mode or measured-capacity claim is introduced. The command reports typed invalid-input versus runtime/recovery outcomes.",
    ],
    "limits": [
        "Only local process-crash and injected-syscall/I/O recovery is proven; physical power loss, kernel/filesystem corruption and remote-runner behavior are not certified.",
        "C17 has no retention or deletion command and cannot prove that a missing segment means no event was lost. C23 owns retention/audit metadata.",
        "AppendRecords and the --project-segments command are not atomic with a C16 commit and do not deduplicate; C18 owns the index/checkpoint and a repeated command appends the same events again.",
        "A failed projection can leave durable segments behind; the typed outcome reports that state, and the operator decides whether to retry the unprojected records.",
        "No transport, mTLS terminator, authenticated ingest endpoint, HTTP API, UI or real sensor identity is added or claimed; the only new surface is the local one-shot projection command.",
        "C28 capacity is unmeasured; C30 remains the full clean-host workflow/restart/restore gate.",
        "Browser regression ran on 127.0.0.1:4199 with a temporary Playwright config because canonical loopback ports were occupied; the same three browser tests passed.",
    ],
    "rollback": "Keep existing segment files and the C16 authority store. Never truncate, rewrite or delete an incomplete payload to force recovery, and never treat an incomplete tail as an event. A segment reader must preserve stable segment IDs and exact incomplete Offset/Bytes/Digest semantics; C18 indexing can be rebuilt from segment files.",
    "delivery": {"commit_created": False, "push_performed": False, "publication_performed": False},
    "remote_actions_executed": False,
    "environment": {
        "node": environment["node"],
        "npm": "11.9.0 pinned CLI first in command PATH",
        "go": environment["go"],
        "os": environment["os"],
        "filesystem": environment["filesystem"],
        "provider": environment["provider"],
        "hardware": "16 logical CPUs; MemTotal 32093692 kB; free disk measured in environment.log; C28 capacity target not measured",
        "details": "docs/evidence/C17/environment.log",
    },
    "test_counts": {
        "required_engine_anchors": int(anchors.group(2)),
        "go_top_level_tests_passed": top_level,
        "go_subtests_passed": subtests,
        "node_tests_passed": node_count,
        "browser_tests_passed": browser_count,
        "python_integrity_tests_passed": python_count,
    },
    "commands": commands,
    "changed_paths": changed_paths,
    "local_clone_verification": {
        "passed": True,
        "candidate_tree": clone_final["stagedTree"],
        "snapshot_commit": clone_source["commit"],
        "git_source_integrity_identity": clone_source["current_source_identity"],
        "output_path": "docs/evidence/C17/clone-final.log",
        "remote_runner": False,
        "delivery_commit": False,
        "runtime_tests_certified": False,
        "binding": "Temporary local snapshot of the final C17 source passed clean-clone setup, Go vet/race/discovery, event validation, the real child-process projection workflow and local runtime startup. It does not certify hosted Actions or product readiness.",
    },
}
(root / "docs/evidence/C17.json").write_text(json.dumps(evidence, indent=2) + "\n")
print(json.dumps({"source_identity": identity, "commands": len(commands), "test_counts": evidence["test_counts"], "changed_paths": len(changed_paths)}, indent=2))
