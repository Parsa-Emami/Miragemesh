"""Prove the C17 segment package and projection command issue no network syscalls."""
import os
import re
import subprocess
from pathlib import Path

root = Path(__file__).resolve().parents[3]
(root / "dist/ci").mkdir(parents=True, exist_ok=True)
environment = {**os.environ, "GOTOOLCHAIN": "go1.27.2", "GOSUMDB": "sum.golang.org", "GOPROXY": "https://proxy.golang.org|direct"}
for name, package in (("c17-events.test", "./internal/events"), ("c17-command.test", "./cmd/miragemesh")):
    subprocess.run(
        ["go", "test", "-c", "-o", f"dist/ci/{name}", package],
        cwd=root,
        check=True,
        env=environment,
    )
trace_events = root / "docs/evidence/C17/network-events.trace"
trace_command = root / "docs/evidence/C17/network-command.trace"
subprocess.run(
    ["strace", "-f", "-e", "trace=network", "-o", str(trace_events), str(root / "dist/ci/c17-events.test"), "-test.run", "^TestSegments", "-test.count=1"],
    cwd=root / "internal/events",
    check=True,
)
subprocess.run(
    ["strace", "-f", "-e", "trace=network", "-o", str(trace_command), str(root / "dist/ci/c17-command.test"), "-test.run", "^TestSegmentProjection", "-test.count=1"],
    cwd=root / "cmd/miragemesh",
    check=True,
)
trace = root / "docs/evidence/C17/network.trace"
trace.write_bytes(trace_events.read_bytes() + trace_command.read_bytes())
calls = re.compile(rb"\b(socket|connect|accept|accept4|bind|listen|sendto|recvfrom|sendmsg|recvmsg)\(")
observed = calls.findall(trace.read_bytes())
if observed:
    raise SystemExit(f"network syscalls observed: {observed!r}")
print("C17 segment tests and the --project-segments workflow passed under strace; zero network syscalls observed")
