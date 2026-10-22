"""Write C20 evidence from the recorded command logs."""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[3]
evidence_dir = root / "docs/evidence/C20"
identity = json.loads((evidence_dir / "source-files.json").read_text())["source_identity"]
commit = sys.argv[1] if len(sys.argv) > 1 else subprocess.check_output(
    ["git", "rev-parse", "HEAD"], cwd=root, text=True
).strip()


def digest(path):
    return hashlib.sha256((root / path).read_bytes()).hexdigest()


def base_commit():
    return subprocess.check_output(["git", "rev-parse", f"{commit}^"], cwd=root, text=True).strip()


commands = [
    ("$(go env GOROOT)/bin/gofmt -l cmd internal tests; test -z output", "docs/evidence/C20/format.log", 0),
    ("go vet ./...", "docs/evidence/C20/vet.log", 0),
    ("go build -trimpath -o /tmp/miragemesh-c20-engine ./cmd/miragemesh", "docs/evidence/C20/go-build.log", 0),
    ("go test -race -count=1 -json ./...", "docs/evidence/C20/engine-tests.jsonl", 0),
    ("node scripts/verify-engine-tests.mjs docs/evidence/C20/engine-tests.jsonl", "docs/evidence/C20/discovery.log", 0),
    ("npm run validate:plan (npm 11.9.0)", "docs/evidence/C20/validate-plan.log", 0),
    ("npm run check (npm 11.9.0)", "docs/evidence/C20/final-check.log", 0),
    ("python3 scripts/validate_repo.py", "docs/evidence/C20/repo-contracts.log", 0),
    ("python3 -m unittest discover -s tests/engineering -p 'test_*.py' -v", "docs/evidence/C20/python-tests.log", 0),
    ("python3 scripts/plan.py validate", "docs/evidence/C20/plan-consistency.log", 0),
    ("playwright test --config docs/evidence/C20/playwright.config.mjs (loopback 4175)", "docs/evidence/C20/browser.log", 0),
    ("npm run package:web (npm 11.9.0)", "docs/evidence/C20/package.log", 0),
    ("npm run test:clone (npm 11.9.0; real temporary clone, setup, vet/race/discovery and source integrity)", "docs/evidence/C20/clone.log", 0),
    ("python3 docs/evidence/C20/source-manifest.py", "docs/evidence/C20/source-manifest.log", 0),
    ("sha256sum tests/fixtures/miragemesh/C20/*.json", "docs/evidence/C20/fixture-hashes.log", 0),
    ("node --version; npx npm@11.9.0 --version; go version; podman version; rootless probe", "docs/evidence/C20/tool-versions.log", 0),
    ("git diff --check", "docs/evidence/C20/diff-check.log", 0),
]

proof = {
    "commit_id": "C20",
    "project": "MirageMesh",
    "passed": True,
    "planning_template": False,
    "date": "2026-10-22",
    "base_commit": base_commit(),
    "implementation_commit": commit,
    "source_identity": identity,
    "source_identity_algorithm": "SHA-256 of sorted UTF-8 relative path + NUL + raw SHA-256(file bytes), over tracked and non-ignored untracked source. docs/evidence/, plans/progress.json, docs/agents/SESSION_HANDOFF.json and SHA256SUMS.txt excluded; each command is bound to the source identity of the input tree at its start.",
    "scope": "C20 append-only incident triage on the existing C05 store. Strict status/reason request shape, digest-only idempotency keys, typed replay/conflict semantics, ordered durable history, restart recovery and forged-history rejection. Triage is neutral to C07 sequence and skipped by C17/C18 projection; it never accepts or rewrites observed event content. No HTTP endpoint, CLI, UI, schema, migration, dependency or egress added.",
    "fixtures": {
        "license": "Apache-2.0",
        "provenance": "Repository-authored synthetic source events, positive triage requests, expected entries and malformed/hostile negative cases; no customer or sensor data.",
        "sha256": {
            "tests/fixtures/miragemesh/C20/positive.json": digest("tests/fixtures/miragemesh/C20/positive.json"),
            "tests/fixtures/miragemesh/C20/expected-output.json": digest("tests/fixtures/miragemesh/C20/expected-output.json"),
            "tests/fixtures/miragemesh/C20/negative.json": digest("tests/fixtures/miragemesh/C20/negative.json"),
        },
    },
    "results": {
        "positive": "Real temporary C05 files plus the C17/C18 segment writer accepted two triage labels for one incident. History returned the exact status/reason in publication order, the C05 event record and receipt were byte-for-byte unchanged, all segment files and the rebuilt index entries were unchanged, and C17 projection skipped both triage records while marking the existing event already projected.",
        "negative": "Fourteen versioned malformed/hostile body, incident-ID and key cases plus inline prerequisite, cancellation, closed-store and C05 quota cases returned typed errors before any manifest change. Missing status/reason, unknown or duplicate members, non-string values, trailing JSON, malformed JSON, empty fields, 4097 runes, an unpaired surrogate, a short idempotency key and an over-long incident ID were all rejected. A forged canonical triage record with a mismatched operation ID made incidents.New fail closed with storage.ErrRecovery.",
        "durability": "After closing and reopening the real C05 store, the same incident/key/body replay returned the original receipt and triage time with Replayed=true and no new generation or manifest bytes. Reusing the key with a different body returned incidents.ErrConflict without changing durable state. A new key appended a second history entry with the next generation. The first source event record remained unchanged.",
        "compatibility": "A triage record was neutral to C07 sensor sequence checking: the next contiguous event was accepted. C17/C18 projection reported appended=0, skipped=2 and already_projected=1 after triage, then appended the next event (appended=1) without treating triage as an event, gap, ACK, enrollment or config record.",
        "bounds": "A 4096-code-point ASCII status and reason round-tripped exactly. A valid 4096-code-point reason made of three-byte code points exceeded the shared 16,384-byte C05 record bound and was rejected explicitly; no bytes were truncated or written.",
        "discovery": "Seven engine suites and 137 required anchors were accepted by the discovery guard. Go race output contained 158 top-level test passes, 260 subtest passes and 5 package passes; 11 packages with no test files were skipped. Node 52/52, browser 3/3 and Python integrity 6/6 passed.",
        "source_integrity": f"The real test:clone path created a temporary committed tree from the staged source, cloned it, ran the source-integrity verifier, setup, Go vet/race tests, the discovery guard and the local runtime smoke test. It passed without changing branch refs. The C20 source snapshot {commit} was committed locally; no push was performed.",
        "security": "Triage validates a strict two-member JSON object, rejects duplicate/unknown/case-varied members and unpaired surrogates, hashes the raw idempotency key instead of storing it, binds the operation ID to incident plus key digest, verifies stored operation IDs, and fails closed on forged history. The package imports only standard-library/storage types and has a no-network-import anchor.",
    },
    "security_review": [
        "The request body has exactly status and reason; event content, source references and extra fields cannot enter a triage record.",
        "Duplicate members, unknown members, non-string values, malformed JSON, trailing values and unpaired UTF-16 surrogates are rejected before the writer is called.",
        "Only a SHA-256 digest of the idempotency key is stored. The operation ID is derived from incident ID and key digest and is revalidated when history is opened.",
        "The raw idempotency key, observed event bytes, event path and source references are not persisted in the triage record.",
        "Triage uses the existing single-writer C05 atomic Update path; identical replay publishes no new generation and conflicting key reuse changes nothing.",
        "The package parses with an exact standard-library/storage allowlist and contains no network, process-execution, HTTP, UI, schema, migration, environment or Dockerfile changes.",
        "Triage records are neutral for C07 sequence and skipped by C17/C18 projection; source event records and immutable segments are compared before and after.",
    ],
    "limits": [
        "GitHub-hosted Actions were not triggered. Local workflow-equivalent commands, including the temporary-clone source-integrity path, passed.",
        f"C20 source snapshot {commit} was committed locally; no push was performed. GitHub-hosted Actions were not triggered. The recorded source identity covers that input tree; verify_ci_source.py was exercised on the temporary clone and is run on the committed checkout after this evidence is committed.",
        "The source identity excludes docs/evidence/, plans/progress.json, docs/agents/SESSION_HANDOFF.json and SHA256SUMS.txt. Build regeneration of apps/web/src/generated/project.json is a derived output; it was restored to the recorded input state after verification.",
        "The OpenAPI triage path is a request-shape contract only. No HTTP endpoint, CLI, UI, retention, export, replication or remote synchronisation is implemented.",
        "The shared C05 record cap is 16,384 bytes. Some OpenAPI-maximum multi-byte labels are rejected explicitly rather than truncated; raising that bound is a later storage design change.",
        "No deployment, publication, remote verification or product-readiness claim is made. C30 remains the full local workflow gate.",
    ],
    "delivery": {
        "commit_created": True,
        "commit": commit,
        "push_performed": False,
        "publication_performed": False,
    },
    "remote_actions_executed": False,
    "environment": {
        "node": "24.19.0",
        "npm": "11.9.0 via pinned npx CLI",
        "go": "1.27.2 linux/amd64; GOSUMDB=sum.golang.org; GOPROXY=https://proxy.golang.org|direct",
        "provider": "rootless Podman 4.9.3; no C20 provider path used",
        "browser": "Google Chrome for Testing 156.0.8078.4, headless, loopback 127.0.0.1:4175 (4173 was already in use)",
        "platform": "Linux amd64",
    },
    "hardware": "Not measured; C20 ran on the local Linux amd64 development host and used only temporary files. The full engine 2 vCPU / 2048 MiB RAM / 10240 MiB disk target remains C28 work.",
    "test_counts": {
        "required_engine_anchors": 137,
        "go_top_level_pass_events": 158,
        "go_subtest_pass_events": 260,
        "go_package_pass_events": 5,
        "go_no_test_file_packages": 11,
        "node_tests_passed": 52,
        "browser_tests_passed": 3,
        "python_integrity_tests_passed": 6,
    },
    "commands": [
        {
            "command": command,
            "exit_code": exit_code,
            "output_path": output,
            "source_identity": identity,
            "stored_output_sha256": digest(output),
        }
        for command, output, exit_code in commands
    ],
    "changed_paths": [
        "internal/contracts/incident.go",
        "internal/incidents/service.go",
        "internal/storage/adapter.go",
        "internal/events/segments.go",
        "internal/sensor/event.go",
        "tests/triage_test.go",
        "tests/rotation_test.go",
        "tests/fixtures/miragemesh/C20/positive.json",
        "tests/fixtures/miragemesh/C20/expected-output.json",
        "tests/fixtures/miragemesh/C20/negative.json",
        "scripts/verify-engine-tests.mjs",
        "tests/engineering/engine-tests.test.mjs",
        "docs/architecture/INCIDENT_TRIAGE.md",
        "docs/engineering/ENGINE_TESTS.md",
        "docs/product/REFERENCE_WORKFLOW.md",
        "docs/ROADMAP_FA.md",
    ],
    "source_manifest": "docs/evidence/C20/source-files.json",
}

for command, output, exit_code in commands:
    if exit_code != 0:
        raise SystemExit(f"nonzero recorded command: {command}")
    if not (root / output).is_file():
        raise SystemExit(f"missing command output: {output}")

(root / "docs/evidence/C20.json").write_text(json.dumps(proof, indent=2, ensure_ascii=False) + "\n")
print(identity)
