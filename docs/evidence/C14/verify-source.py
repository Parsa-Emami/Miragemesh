"""Verify C14's source inventory without modifying the checkout."""
from pathlib import Path
import hashlib,json,subprocess
root=Path(__file__).resolve().parents[3]
paths=subprocess.check_output(['git','ls-files','--cached','--others','--exclude-standard','-z'],cwd=root).decode().split('\0')
excluded={'SHA256SUMS.txt','plans/progress.json','docs/agents/SESSION_HANDOFF.json'}
files={};digest=hashlib.sha256()
for name in sorted(set(paths)-{''}):
 if name in excluded or name.startswith('docs/evidence/'):continue
 path=root/name
 if path.is_file():
  value=hashlib.sha256(path.read_bytes()).hexdigest();files[name]=value;digest.update(name.encode()+b'\0'+bytes.fromhex(value))
identity='sha256:'+digest.hexdigest()
expected=json.loads((root/'docs/evidence/C14/source-files.json').read_text())
assert expected=={'source_identity':identity,'files':files},'C14 source inventory mismatch'
assert json.loads((root/'docs/evidence/C14.json').read_text())['source_identity']==identity
progress=json.loads((root/'plans/progress.json').read_text())
assert next(x for x in progress['commits'] if x['id']=='C14')['source_identity']==identity
print(identity+'; '+str(len(files))+' source files verified')
