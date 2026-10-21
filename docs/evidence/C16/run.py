import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

root = Path(__file__).resolve().parents[3]
evidence = root / "docs/evidence/C16"
name, *argv = sys.argv[1:]
env = os.environ.copy()
env.update(
    GOTOOLCHAIN="go1.27.2",
    GOSUMDB="sum.golang.org",
    GOPROXY="https://proxy.golang.org|direct",
)
npm_bin = "/home/amirreza/.npm/_npx/5ed1df33febb5bb0/node_modules/.bin"
env["PATH"] = npm_bin + os.pathsep + env["PATH"]
paths = subprocess.check_output(
    ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=root
).decode().split("\0")
digest = hashlib.sha256()
for relative in sorted(set(paths) - {""}):
    if relative.startswith("docs/evidence/") or relative in {
        "SHA256SUMS.txt", "plans/progress.json", "docs/agents/SESSION_HANDOFF.json"
    }:
        continue
    path = root / relative
    if path.is_file():
        digest.update(relative.encode() + b"\0" + hashlib.sha256(path.read_bytes()).digest())
identity = "sha256:" + digest.hexdigest()
started = time.monotonic()
with (evidence / f"{name}.log").open("wb") as output:
    result = subprocess.run(argv, cwd=root, env=env, stdout=output, stderr=subprocess.STDOUT)
item = {
    "argv": argv,
    "exit_code": result.returncode,
    "output_path": f"docs/evidence/C16/{name}.log",
    "source_identity": identity,
    "elapsed_seconds": round(time.monotonic() - started, 3),
    "environment_overrides": {
        "GOTOOLCHAIN": env["GOTOOLCHAIN"],
        "GOSUMDB": env["GOSUMDB"],
        "GOPROXY": env["GOPROXY"],
        "npm_cli": "11.9.0 via pinned npm bin first in PATH",
    },
    "stored_output_sha256": hashlib.sha256((evidence / f"{name}.log").read_bytes()).hexdigest(),
}
with (evidence / "commands.jsonl").open("a") as output:
    output.write(json.dumps(item) + "\n")
print(json.dumps(item))
print((evidence / f"{name}.log").read_text(errors="replace")[-1600:])
sys.exit(result.returncode)
