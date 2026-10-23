import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, chmodSync, symlinkSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const invoke = args => spawnSync('dist/engine/miragemesh', args, { encoding: 'utf8', timeout: 15000 });
const common = dir => ['--verify-update', '--update-state-dir', join(dir, 'state'), '--update-publisher-key-file', join(dir, 'publisher.pub'), '--update-recovery-key-file', join(dir, 'recovery.pub'), '--update-platform', 'linux/amd64', '--update-max-operations', '128', '--update-max-bytes', '2097152', '--update-max-manifest-bytes', '131072', '--update-max-sensors', '16', '--update-max-artifact-bytes', '1048576', '--update-max-metadata-ttl-seconds', '3600', '--update-max-recovery-ttl-seconds', '600'];

function seed(t){const dir=mkdtempSync(join(tmpdir(),'miragemesh-c25-cli-'));t.after(()=>rmSync(dir,{recursive:true,force:true}));const r=spawnSync('go',['run','./tests/fixtures/miragemesh/C25/seed',dir],{encoding:'utf8',timeout:30000});assert.equal(r.status,0,r.stderr);return dir;}

test('update CLI persists revocation and exact scoped recovery across independent processes',t=>{
 const dir=seed(t),args=common(dir);
 let r=invoke([...args,'--update-action','status']);assert.equal(r.status,0,r.stderr);assert.equal(JSON.parse(r.stdout).snapshot.sensors[0].version,4);
 r=invoke([...args,'--update-action','accept-metadata','--update-metadata-file',join(dir,'metadata-2.json'),'--update-signature-file',join(dir,'metadata-2.sig')]);assert.equal(r.status,0,r.stderr);assert.equal(JSON.parse(r.stdout).metadata.revision,2);
 const verify=[...args,'--update-action','verify','--update-sensor','sensor-25','--update-version','4','--update-artifact-file',join(dir,'release-4.bin')];
 r=invoke(verify);assert.equal(r.status,1);assert.equal(JSON.parse(r.stdout).error_kind,'revoked_version');
 const recovery=[...args,'--update-action','verify','--update-sensor','sensor-25','--update-version','2','--update-artifact-file',join(dir,'release-2.bin'),'--update-grant-file',join(dir,'grant.json'),'--update-grant-signature-file',join(dir,'grant.sig')];
 r=invoke(recovery);assert.equal(r.status,0,r.stderr);const original=JSON.parse(r.stdout).result;assert.equal(original.version,2);assert.equal(original.high_water_version,4);assert.equal(original.recovery,true);
 r=invoke(recovery);assert.equal(r.status,0,r.stderr);assert.equal(JSON.parse(r.stdout).result.replayed,true);assert.deepEqual(JSON.parse(r.stdout).result.receipt,original.receipt);
 r=invoke([...args,'--update-action','status']);assert.equal(r.status,0,r.stderr);assert.equal(JSON.parse(r.stdout).snapshot.sensors[0].status,'verified');
 const before=readFileSync(join(dir,'state','manifest.json'),'utf8');
 writeFileSync(join(dir,'release-2.bin'),'modified synthetic artifact');r=invoke(recovery);assert.equal(r.status,1);assert.equal(JSON.parse(r.stdout).error_kind,'artifact_mismatch');assert.equal(readFileSync(join(dir,'state','manifest.json'),'utf8'),before);
});

test('update CLI rejects unrelated flags, unsafe files and missing trust prerequisites before mutation',t=>{
 const dir=seed(t),args=common(dir);const before=readFileSync(join(dir,'state','manifest.json'),'utf8');
 for(const extra of [['--version'],['--project-segments'],['--listen','127.0.0.1:0'],['--update-grant-file',join(dir,'grant.json')],['unexpected']]){const r=invoke([...args,'--update-action','status',...extra]);assert.equal(r.status,2,r.stderr);}
 assert.equal(invoke(['--verify-update']).status,2);
 const accept=[...args,'--update-action','accept-metadata','--update-metadata-file',join(dir,'metadata-2.json'),'--update-signature-file',join(dir,'metadata-2.sig')];
 chmodSync(join(dir,'metadata-2.json'),0o666);let r=invoke(accept);assert.equal(r.status,2);chmodSync(join(dir,'metadata-2.json'),0o600);
 symlinkSync(join(dir,'metadata-2.json'),join(dir,'linked.json'));r=invoke([...accept,'--update-metadata-file',join(dir,'linked.json')]);assert.notEqual(r.status,0);
 writeFileSync(join(dir,'metadata-2.sig'),Buffer.alloc(64));r=invoke(accept);assert.equal(r.status,1);assert.equal(JSON.parse(r.stdout).error_kind,'untrusted_signature');
 assert.equal(readFileSync(join(dir,'state','manifest.json'),'utf8'),before);
});
