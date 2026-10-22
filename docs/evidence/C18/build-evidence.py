"""Build C18's evidence from recorded command logs and the final source identity."""
import hashlib
import json
import re
import subprocess
from pathlib import Path

root = Path(__file__).resolve().parents[3]
evidence_dir = root / "docs/evidence/C18"
commands = [json.loads(line) for line in (evidence_dir / "commands.jsonl").read_text().splitlines()]
source = json.loads((evidence_dir / "source-files.json").read_text())
identity = source["source_identity"]
assert commands and all(command["exit_code"] == 0 for command in commands)
assert all(command["source_identity"] == identity for command in commands)
assert len(commands) == 18, f"expected 18 recorded commands, got {len(commands)}"

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
assert anchors and anchors.group(1) == "5" and anchors.group(2) == "123"
node_tests = re.search(r"ℹ pass (\d+)", log("final-check"))
browser_tests = re.search(r"(\d+) passed", log("browser"))
python_tests = re.search(r"Ran (\d+) tests", log("python-tests"))
assert node_tests and browser_tests and python_tests
node_count = int(node_tests.group(1))
browser_count = int(browser_tests.group(1))
python_count = int(python_tests.group(1))
assert "All C18 index tests passed" not in log("index-tests")
assert log("index-tests").count("--- PASS: TestIndex") >= 7
assert "--- PASS: TestSegmentProjectionWorkflowDeduplicatesAndReportsIndexCoverage" in log("runtime-projection")

environment = {}
for line in log("environment").splitlines():
    try:
        item = json.loads(line)
    except json.JSONDecodeError:
        continue
    argv = item.get("argv")
    if argv == ["node", "--version"]:
        environment["node"] = item["output"].removeprefix("v")
    elif argv == ["npm", "--version"]:
        environment["npm"] = item["output"]
    elif argv == ["go", "version"]:
        environment["go"] = "1.27.2 with official checksum database enabled for commands"
    elif argv == ["podman", "--version"]:
        environment["provider"] = "rootless Podman 4.9.3; pinned Alpine image digest present"
    elif argv == ["uname", "-srmo"]:
        environment["os"] = item["output"].replace(" GNU/Linux", "")
    elif argv == ["findmnt", "-T", ".", "-n", "-o", "FSTYPE"]:
        environment["filesystem"] = item["output"]
assert environment.get("node") == "24.19.0" and environment.get("npm") == "11.9.0"
assert environment.get("filesystem") == "ext4"

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

fixture_names = ["positive.json", "expected-output.json", "negative.json"]
fixture_hashes = {
    f"tests/fixtures/miragemesh/C18/{name}": hashlib.sha256((root / "tests/fixtures/miragemesh/C18" / name).read_bytes()).hexdigest()
    for name in fixture_names
}
fixtures = {
    "license": "Apache-2.0",
    "provenance": "Repository-authored synthetic C18 events, expected rebuilt-index semantics and negative cases; small test-policy limits are not product defaults or capacity claims.",
    "sha256": fixture_hashes,
}

status_lines = subprocess.check_output(
    ["git", "status", "--porcelain=v1", "-uall"], cwd=root, text=True
).splitlines()
changed_paths = sorted({line[3:] for line in status_lines if len(line) > 3})
assert "docs/evidence/C18.json" in changed_paths
assert "docs/evidence/C18/build-evidence.py" in changed_paths
assert "internal/events/index.go" in changed_paths
assert "tests/rebuild_test.go" in changed_paths
assert "cmd/miragemesh/segments.go" in changed_paths
assert "docs/agents/SESSION_HANDOFF.json" in changed_paths

evidence = {
    "commit_id": "C18",
    "project": "MirageMesh",
    "passed": True,
    "planning_template": False,
    "date": "2026-10-22",
    "base_commit": "d2023f5cb8168237e8d8779d892fc0b912e12fe8",
    "source_identity": identity,
    "source_manifest": "docs/evidence/C18/source-files.json",
    "source_identity_algorithm": "SHA-256 of sorted UTF-8 relative path + NUL + raw SHA-256(file bytes), over tracked and non-ignored untracked source. docs/evidence/, plans/progress.json, docs/agents/SESSION_HANDOFF.json and SHA256SUMS.txt excluded; each command records identity at start.",
    "scope": "F12 derived event index and deduplication checkpoint rebuilt from committed C17 segments: in-memory rebuild at Open, typed identity conflicts, exact-repeat counting, index coverage with exclusive missing ordinal ranges and incomplete tails, and deduplicated --project-segments workflow outcomes. No durable index file, new command, schema, migration, dependency, HTTP/UI surface, egress, retention or full-product readiness claim.",
    "owner_scope_resolution": "The C18 card names internal/events/index.go and tests/rebuild_test.go. The implementation also extends internal/events/segments.go so the index is actually rebuilt at Open and used by Append/AppendRecords, and cmd/miragemesh/segments.go plus its test so the typed outcome has a real engine caller. No database schema, migration, environment file, Dockerfile, dependency or sibling-repository import was changed. C17's segment format, crash recovery and incomplete-tail semantics are preserved; C05/C16 authority and receipt behavior are untouched. The index is derived state only: deleting it (closing the process) is recovered by reopening, while deleting a committed segment stays visible as a missing ordinal range and is never treated as proof that no event was ingested. Sequence collisions with different event IDs are not rejected as identity conflicts because C17 append behavior permits them; identity is the C04 sensor/event pair, matching the card's modified-byte and identity requirements.",
    "fixtures": fixtures,
    "results": {
        "positive": "Five synthetic events over two sensors produce three stable segments. Open rebuilds five unique entries with exact sensor/event identity, sequence, segment ID, one-based record number, payload SHA-256 and byte length; reopening produces the same snapshot. A repeated --project-segments child process appends nothing, reports already_projected=5, index_records=5, index_sensors=2, index_complete=true and leaves every segment byte unchanged.",
        "negative": "A one-byte change that keeps a record valid is caught as a typed conflict when the rebuilt digest is compared with the C05 record; a one-byte change that makes the record invalid fails Open with ErrRecovery. A direct conflicting append returns ErrIndexConflict without changing segment bytes, an exact duplicate is tolerated and counted once, and a segment directory containing the same identity with different bytes fails Open with ErrIndexConflict. The workflow surfaces error_kind conflict.",
        "rebuild": "Removing one middle sealed segment and reopening rebuilds a three-entry index over the remaining segments, reports the exclusive missing range {after:1,before:3}, and reports complete=false. Lookup of the removed identities returns false and the entries slice never claims them. Re-projecting the C05 snapshot appends exactly the two absent events, counts the three present ones as already projected, keeps the ordinal gap explicit and produces five unique entries with zero duplicates.",
        "incomplete_tail": "Truncating the active segment removes its torn tail from the index. The preserved tail keeps its C17 Offset/Bytes/Digest metadata, index_complete is false, and the torn event identity is absent rather than reported as ingested.",
        "discovery": "Five engine suites and 123 required test anchors executed and were accepted by the discovery guard; the new C18 anchors cannot be skipped or omitted.",
        "network": "The C18 index tests, C17 segment tests and --project-segments workflow passed under strace with zero socket/connect/bind/listen/accept or message-send/receive syscalls. internal/events/index.go has an errors-only import allowlist.",
        "workflow": "Build, explicit index and runtime-projection regressions, browser, package checksum, repository contract, Python integrity, plan validation, final check, next-task and clean-clone equivalents are recorded with exits and logs. No GitHub-hosted run or publication occurred.",
    },
    "security_review": [
        "Index identity conflicts are typed and rejected before any file is created or changed; the writer stays usable so evidence can be repaired.",
        "Open fails closed on conflicting committed records instead of building a trusted but ambiguous index.",
        "A torn or invalid record is excluded from the index and keeps its C17 preserved-tail metadata; it is never reported as an event.",
        "Index coverage distinguishes incomplete coverage from non-ingestion: absence from the index is documented and tested as non-proof.",
        "The index is derived and rebuilt through the existing os.Root-safe segment reader; it adds no durable file, parser, privileged path or new trust boundary.",
        "The index has an errors-only import allowlist and no network, process-execution, container or filesystem-write path of its own.",
        "C05 records and C16 receipts/ACKs remain authoritative and unchanged; projection reads an owned snapshot and writes only segments.",
        "Severity, alerting, retention and deletion remain outside C18; no claim is made that a deleted segment proves event loss or non-loss.",
    ],
    "limits": [
        "Only local process and filesystem behavior is proven; physical power loss, kernel/filesystem corruption and remote-runner behavior are not certified.",
        "The index is O(records) memory bounded indirectly by the mandatory segment record/segment limits; no measured capacity claim is made (C28).",
        "Deleting the lowest or highest present segment creates no internal ordinal gap and is indistinguishable from a short history; C23 must preserve an ordinal high-water mark.",
        "Absence from the index never proves non-ingestion. C15 gaps, C23 retention and missing segments remain separate evidence.",
        "Exact duplicate records are tolerated and counted for backward compatibility with stores projected before C18; they are not removed from disk.",
        "Sequence collisions with different event IDs are not part of the identity conflict rule; C04/C07 validation and C05 authority remain responsible for sequence semantics.",
        "No signer or trust anchor is introduced by C18, so the card's wrong/untrusted-signer negative case has no surface here; modified bytes, conflicting identity and missing evidence are covered.",
        "No retention, alerting, trace viewer, authenticated ingest, published decoy surface, HTTP API or UI is added; C30 remains the clean-host workflow/restart/restore gate.",
        "Browser regression ran on 127.0.0.1:4199 with a temporary Playwright config inside docs/evidence/C18 because canonical loopback ports were occupied; the same three browser tests passed.",
    ],
    "rollback": "Close the writer and keep the committed segment files and the C05/C16 authority store. Do not delete or rewrite a segment to clear an index conflict; repair the conflicting evidence or restore a compatible copy. The next Open rebuilds the index from whatever complete records exist, and any missing segment ordinal remains an explicit coverage fact.",
    "delivery": {"commit_created": False, "push_performed": False, "publication_performed": False},
    "remote_actions_executed": False,
    "environment": {
        "node": environment["node"],
        "npm": environment["npm"] + " pinned CLI first in command PATH",
        "go": environment["go"],
        "os": environment["os"],
        "filesystem": environment["filesystem"],
        "provider": environment["provider"],
        "hardware": "16 logical CPUs; MemTotal 32093692 kB; free disk measured in environment.log; C28 capacity target not measured",
        "details": "docs/evidence/C18/environment.log",
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
        "output_path": "docs/evidence/C18/clone-final.log",
        "remote_runner": False,
        "delivery_commit": False,
        "runtime_tests_certified": False,
        "binding": "Temporary local snapshot of the final C18 source passed clean-clone setup, Go vet/race/discovery, event validation, the deduplicating index regressions and local runtime startup. It does not certify hosted Actions or product readiness.",
    },
}
(root / "docs/evidence/C18.json").write_text(json.dumps(evidence, indent=2) + "\n")
print(json.dumps({"source_identity": identity, "commands": len(commands), "test_counts": evidence["test_counts"], "changed_paths": len(changed_paths)}, indent=2))
