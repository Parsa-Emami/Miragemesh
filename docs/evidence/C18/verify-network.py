"""Prove the C18 index, segment package and projection command issue no network syscalls."""
import os
import re
import subprocess
from pathlib import Path

root = Path(__file__).resolve().parents[3]
(root / "dist/ci").mkdir(parents=True, exist_ok=True)
environment = {**os.environ, "GOTOOLCHAIN": "go1.27.2", "GOSUMDB": "sum.golang.org", "GOPROXY": "https://proxy.golang.org|direct"}
for name, package in (
    ("c18-events.test", "./internal/events"),
    ("c18-command.test", "./cmd/miragemesh"),
    ("c18-tests.test", "./tests"),
):
    subprocess.run(
        ["go", "test", "-c", "-o", f"dist/ci/{name}", package],
        cwd=root,
        check=True,
        env=environment,
    )
trace_events = root / "docs/evidence/C18/network-events.trace"
trace_index = root / "docs/evidence/C18/network-index.trace"
trace_command = root / "docs/evidence/C18/network-command.trace"
subprocess.run(
    ["strace", "-f", "-e", "trace=network", "-o", str(trace_events), str(root / "dist/ci/c18-events.test"), "-test.run", "^TestSegments", "-test.count=1"],
    cwd=root / "internal/events",
    check=True,
)
subprocess.run(
    ["strace", "-f", "-e", "trace=network", "-o", str(trace_index), str(root / "dist/ci/c18-tests.test"), "-test.run", "^TestIndex", "-test.count=1"],
    cwd=root / "tests",
    check=True,
)
subprocess.run(
    ["strace", "-f", "-e", "trace=network", "-o", str(trace_command), str(root / "dist/ci/c18-command.test"), "-test.run", "^TestSegmentProjection", "-test.count=1"],
    cwd=root / "cmd/miragemesh",
    check=True,
)
trace = root / "docs/evidence/C18/network.trace"
trace.write_bytes(trace_events.read_bytes() + trace_index.read_bytes() + trace_command.read_bytes())
calls = re.compile(rb"\b(socket|connect|accept|accept4|bind|listen|sendto|recvfrom|sendmsg|recvmsg)\(")
observed = calls.findall(trace.read_bytes())
if observed:
    raise SystemExit(f"network syscalls observed: {observed!r}")
print("C18 index, segment and --project-segments tests passed under strace; zero network syscalls observed")
