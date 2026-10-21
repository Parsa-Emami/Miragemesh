"""Prove the C15 overflow paths issue no network syscalls."""
import os
import re
import subprocess
from pathlib import Path

root = Path(__file__).resolve().parents[3]
(root / "dist/ci").mkdir(parents=True, exist_ok=True)
subprocess.run(
    ["go", "test", "-c", "-o", "dist/ci/c15-spool.test", "./tests"],
    cwd=root,
    check=True,
    env={**os.environ, "GOTOOLCHAIN": "go1.27.2", "GOSUMDB": "sum.golang.org", "GOPROXY": "https://proxy.golang.org|direct"},
)
trace = root / "docs/evidence/C15/network.trace"
subprocess.run(
    ["strace", "-f", "-e", "trace=network", "-o", str(trace), str(root / "dist/ci/c15-spool.test"), "-test.run", "^TestSpoolOverflow", "-test.count=1"],
    cwd=root / "tests",
    check=True,
)
calls = re.compile(rb"\b(socket|connect|accept|accept4|bind|listen|sendto|recvfrom|sendmsg|recvmsg)\(")
observed = calls.findall(trace.read_bytes())
if observed:
    raise SystemExit(f"network syscalls observed: {observed!r}")
print("C15 overflow tests passed under strace; zero network syscalls observed")
