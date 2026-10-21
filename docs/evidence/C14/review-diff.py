"""Review the whole candidate diff without modifying the real Git index."""
import os,subprocess,tempfile
from pathlib import Path
root=Path(__file__).resolve().parents[3]
with tempfile.TemporaryDirectory(prefix='miragemesh-c14-review-') as directory:
 env=os.environ.copy();env['GIT_INDEX_FILE']=directory+'/index'
 def git(*args):return subprocess.check_output(['git',*args],cwd=root,env=env,text=True)
 git('read-tree','HEAD');git('add','-A','--','.')
 subprocess.run(['git','diff','--cached','--check'],cwd=root,env=env,check=True)
 paths=git('diff','--cached','--name-only').splitlines()
 for path in paths:
  parts=Path(path).parts
  assert not any(x in {'migrations','Dockerfile'} for x in parts),path
  assert not any(x=='.env' or x.startswith('.env.') for x in parts),path
  assert not path.startswith('contracts/'),path
 for path in ['go.mod','package.json','package-lock.json']:
  assert subprocess.check_output(['git','show','HEAD:'+path],cwd=root)==(root/path).read_bytes(),path
 print(git('diff','--cached','--stat','--','.',':(exclude)docs/evidence/**').strip())
 print('Reviewed candidate changes:',len(paths))
 print('Protected paths, event schemas, manifests and dependency locks unchanged; real index preserved.')
 # Only this task was present when work began; the user index must remain empty.
 subprocess.run(['git','diff','--cached','--quiet'],cwd=root,env={k:v for k,v in env.items() if k!='GIT_INDEX_FILE'},check=True)
