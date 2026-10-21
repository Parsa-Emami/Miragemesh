import subprocess,os,json,shutil,hashlib
from pathlib import Path
commands=[['node','--version'],['npm','--version'],['go','version'],['podman','--version'],['podman','info','--format','{{.Host.Security.Rootless}}'],['podman','image','inspect','docker.io/library/alpine@sha256:865b95f46d98cf867a156fe4a135ad3fe50d2056aa3f25ed31662dff6da4eb62','--format','{{.Digest}} {{.Architecture}}/{{.Os}}'],['uname','-srmo'],['findmnt','-T','.','-n','-o','FSTYPE'],['git','rev-parse','HEAD']]
for c in commands:print(json.dumps({'argv':c,'output':subprocess.check_output(c,text=True).strip()}))
print(json.dumps({'logical_cpus':os.cpu_count(),'memory_total':Path('/proc/meminfo').read_text().splitlines()[0],'free_disk_bytes':shutil.disk_usage('.').free,'capacity_target_measured':False,'locks':{p:hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in ['package-lock.json','go.mod']}}))
