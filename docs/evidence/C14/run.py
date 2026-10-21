import sys,subprocess,os,json,time,hashlib
from pathlib import Path
root=Path(__file__).resolve().parents[3]; evidence=root/'docs/evidence/C14'
name=sys.argv[1]; argv=sys.argv[2:]
env=os.environ.copy(); env.update(GOTOOLCHAIN='go1.27.2',GOSUMDB='sum.golang.org',GOPROXY='https://proxy.golang.org|direct')
env['PATH']='/home/amirreza/.npm/_npx/5ed1df33febb5bb0/node_modules/.bin:'+env['PATH']
paths=subprocess.check_output(['git','ls-files','--cached','--others','--exclude-standard','-z'],cwd=root).decode().split('\0')
h=hashlib.sha256()
for p in sorted(set(paths)-{''}):
 if p.startswith('docs/evidence/') or p in ('SHA256SUMS.txt','plans/progress.json','docs/agents/SESSION_HANDOFF.json'):continue
 file=root/p
 if file.is_file():h.update(p.encode()+b'\0'+hashlib.sha256(file.read_bytes()).digest())
start=time.monotonic()
with (evidence/(name+'.log')).open('wb') as out:r=subprocess.run(argv,cwd=root,env=env,stdout=out,stderr=subprocess.STDOUT)
item={'argv':argv,'exit_code':r.returncode,'output_path':f'docs/evidence/C14/{name}.log','source_identity':'sha256:'+h.hexdigest(),'elapsed_seconds':round(time.monotonic()-start,3),'environment_overrides':{'GOTOOLCHAIN':env['GOTOOLCHAIN'],'GOSUMDB':env['GOSUMDB'],'GOPROXY':env['GOPROXY'],'npm_cli':'11.9.0 via pinned npm bin first in PATH'}}
with (evidence/'commands.jsonl').open('a') as out:out.write(json.dumps(item)+'\n')
print(json.dumps(item));print((evidence/(name+'.log')).read_text(errors='replace')[-1200:])
sys.exit(r.returncode)
