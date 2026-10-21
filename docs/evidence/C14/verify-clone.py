import os,subprocess,tempfile,json,sys
from pathlib import Path
sys.path.insert(0,str(Path.cwd()/"scripts"))
from verify_ci_source import tree_files
from pathlib import Path
with tempfile.TemporaryDirectory(prefix='miragemesh-c14-index-') as d:
 env=os.environ.copy();env['GIT_INDEX_FILE']=d+'/index'
 subprocess.run(['git','read-tree','HEAD'],env=env,check=True)
 subprocess.run(['git','add','-A','--','.'],env=env,check=True)
 subprocess.run(['git','diff','--cached','--check'],env=env,check=True)
 tree=subprocess.check_output(['git','write-tree'],env=env,text=True).strip()
 source=json.loads(Path('docs/evidence/C14/source-files.json').read_text())
 files=tree_files(Path.cwd(),tree)
 actual={name:item['sha256'] for name,item in files.items() if not name.startswith('docs/evidence/') and name not in {'SHA256SUMS.txt','plans/progress.json','docs/agents/SESSION_HANDOFF.json'}}
 assert actual==source['files'], 'Candidate source differs from verified C14 inventory'
 print('Candidate tree: '+tree+'; C14 source: '+source['source_identity'],flush=True)
 subprocess.run(['npm','run','test:clone'],env=env,check=True)
