import os,tempfile,subprocess
from pathlib import Path
root=Path(__file__).resolve().parents[3]
fd,name=tempfile.mkstemp(prefix='miragemesh-c11-index-');os.close(fd);os.unlink(name)
env=os.environ.copy();env['GIT_INDEX_FILE']=name
try:
    subprocess.run(['git','read-tree','HEAD'],cwd=root,env=env,check=True)
    subprocess.run(['git','add','-A'],cwd=root,env=env,check=True)
    subprocess.run(['git','diff','--cached','--check'],cwd=root,env=env,check=True)
    staged=subprocess.check_output(['git','diff','--cached','--stat'],cwd=root,env=env,text=True)
    (root/'docs/evidence/C11/candidate-diff-stat.log').write_text(staged)
    result=subprocess.run(['npm','run','test:clone'],cwd=root,env=env)
    raise SystemExit(result.returncode)
finally:
    for suffix in ['', '.lock']:
        try:os.unlink(name+suffix)
        except FileNotFoundError:pass
