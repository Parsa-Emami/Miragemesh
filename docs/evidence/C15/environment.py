import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

root = Path(__file__).resolve().parents[3]
commands = [
    ["node", "--version"],
    ["npm", "--version"],
    ["go", "version"],
    ["podman", "--version"],
    ["podman", "info", "--format", "{{.Host.Security.Rootless}}"],
    ["podman", "image", "inspect", "docker.io/library/alpine@sha256:865b95f46d98cf867a156fe4a135ad3fe50d2056aa3f25ed31662dff6da4eb62", "--format", "{{.Digest}} {{.Architecture}}/{{.Os}}"],
    ["uname", "-srmo"],
    ["findmnt", "-T", ".", "-n", "-o", "FSTYPE"],
    ["git", "rev-parse", "HEAD"],
]
for argv in commands:
    print(json.dumps({"argv": argv, "output": subprocess.check_output(argv, text=True, cwd=root).strip()}))
locks = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in ("package-lock.json", "go.mod")}
print(json.dumps({"logical_cpus": os.cpu_count(), "memory_total": Path("/proc/meminfo").read_text().splitlines()[0], "free_disk_bytes": shutil.disk_usage(root).free, "capacity_target_measured": False, "locks": locks}))
