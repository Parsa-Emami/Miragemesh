import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { validateUpdateSnapshot } from '../../apps/web/src/lib/updates.mjs';
import { readEngineUpdates } from '../../scripts/serve-web.mjs';

function fixture(){return {schema_version:'1',platform:'linux/amd64',publisher_fingerprint:'a'.repeat(64),recovery_fingerprint:'b'.repeat(64),observed_at:'2026-01-01T00:00:00Z',sensors:[{sensor_id:'sensor-25',revision:2,issued_at:'2026-01-01T00:00:00Z',expires_at:'2026-01-01T01:00:00Z',metadata_digest:'c'.repeat(64),releases:[{version:2,sha256:'d'.repeat(64),length:100}],revoked_versions:[3,4],version:2,high_water_version:4,verified_revision:2,verified_at:'2026-01-01T00:00:00Z',recovery:true,status:'verified'}]};}

test('update snapshot rejects misleading authority, duplicate releases, private fields and expiry boundary truncation',()=>{
 const valid=fixture();assert.equal(validateUpdateSnapshot(valid),valid);
 for(const mutate of [v=>v.publisher_fingerprint='bad',v=>v.recovery_fingerprint=v.publisher_fingerprint,v=>v.sensors.push(structuredClone(v.sensors[0])),v=>v.sensors[0].releases.push({...v.sensors[0].releases[0]}),v=>v.sensors[0].high_water_version=1,v=>v.sensors[0].verified_revision=3,v=>v.sensors[0].signature='secret',v=>v.sensors[0].revoked_versions.push(2),v=>v.observed_at='2026-01-01T01:00:00Z',v=>v.sensors[0].releases[0].length=0]){const value=fixture();mutate(value);assert.throws(()=>validateUpdateSnapshot(value));}
 const boundary=fixture();boundary.observed_at='2026-01-01T00:59:59.999999999Z';validateUpdateSnapshot(boundary);boundary.sensors[0].expires_at='2026-01-01T00:59:59.999999999Z';assert.throws(()=>validateUpdateSnapshot(boundary));boundary.sensors[0].status='expired';validateUpdateSnapshot(boundary);
});

test('update proxy confines requests, validates actual response bytes and refuses redirects or oversized data',async t=>{
 let mode='valid';const server=http.createServer((req,res)=>{assert.equal(req.url,'/api/v1/updates');if(mode==='redirect'){res.writeHead(302,{Location:'https://example.invalid/update'});res.end();return;}res.writeHead(200);res.end(mode==='large'?' '.repeat(1048577):JSON.stringify(mode==='invalid'?{status:'verified'}:fixture()));});
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));t.after(()=>new Promise(resolve=>server.close(resolve)));const address=`127.0.0.1:${server.address().port}`;
 assert.equal((await readEngineUpdates(address)).sensors[0].version,2);
 for(mode of ['redirect','large','invalid'])await assert.rejects(readEngineUpdates(address));
 await assert.rejects(readEngineUpdates('example.invalid:443'));
});

test('update read-only API contract matches both published formats',async()=>{
 const api=JSON.parse(await readFile('contracts/openapi.v1.json','utf8'));assert.equal(api.paths['/updates'].get.operationId,'getUpdateStatus');assert.equal(api.paths['/updates'].post,undefined);assert.ok(api.components.schemas.UpdateSnapshot);assert.match(await readFile('contracts/openapi.v1.yaml','utf8'),/getUpdateStatus/);
});
