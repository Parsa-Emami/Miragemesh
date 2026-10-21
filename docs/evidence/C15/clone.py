"""Run the real clean-clone workflow against a temporary index of this source."""
import os
import subprocess
from pathlib import Path

root = Path(__file__).resolve().parents[3]
index = Path(subprocess.check_output(["git", "rev-parse", "--git-path", "index"], cwd=root, text=True).strip())
if not index.is_absolute():
    index = root / index
original_index = index.read_bytes() if index.exists() else None
env = os.environ.copy()
env["PATH"] = "/home/amirreza/.npm/_npx/5ed1df33febb5bb0/node_modules/.bin" + os.pathsep + env["PATH"]
try:
    subprocess.run(["git", "read-tree", "HEAD"], check=True, env=env)
    subprocess.run(["git", "add", "-A"], check=True, env=env)
    env.update(
        GOTOOLCHAIN="go1.27.2",
        GOSUMDB="sum.golang.org",
        GOPROXY="https://proxy.golang.org|direct",
    )
    subprocess.run(["npm", "run", "test:clone"], check=True, cwd=root, env=env)
finally:
    if original_index is None:
        index.unlink(missing_ok=True)
    else:
        index.write_bytes(original_index)
