import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { readFileSync } from 'node:fs';
import Ajv from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import { once } from 'node:events';
import { validateCertificateSnapshot } from '../../apps/web/src/lib/certificates.mjs';
import { createWebServer } from '../../scripts/serve-web.mjs';

function snapshot() {
 return { schema_version: '1', issuer_fingerprint: 'a'.repeat(64), observed_at: '2026-01-01T02:00:00Z', sensors: [{ sensor_id: 'sensor-24', revision: 2, fingerprint: 'b'.repeat(64), previous_fingerprint: 'c'.repeat(64), overlap_until: '2026-01-01T01:00:00Z', not_after: '2026-01-02T00:00:00Z', status: 'current', recovery_available: true }] };
}

test('certificate boundary rejects inconsistent dates, scope duplication, status and secret fields', () => {
 const value = snapshot(); assert.equal(validateCertificateSnapshot(value), value);
 for (const change of [v => { v.schema_version = '2'; }, v => { v.sensors[0].status = 'overlap'; }, v => { v.sensors[0].recovery_available = false; }, v => { v.sensors[0].revision = 0; }, v => { v.sensors[0].fingerprint = 'forged'; }, v => { v.sensors[0].fingerprint = v.sensors[0].previous_fingerprint; }, v => { v.sensors.push(structuredClone(v.sensors[0])); }, v => { v.sensors[0].private_key = 'untrusted'; }, v => { v.observed_at = 'yesterday'; }]) {
  const invalid = structuredClone(value); change(invalid); assert.throws(() => validateCertificateSnapshot(invalid), /invalid/);
 }
});

test('certificate proxy accepts a bounded snapshot and refuses redirects, malformed, oversized and unavailable upstreams', async () => {
 for (const mode of ['valid', 'redirect', 'malformed', 'oversized', 'unavailable']) {
  const upstream = http.createServer((req, res) => {
   assert.equal(req.url, '/api/v1/certificates'); assert.equal(req.method, 'GET');
   if (mode === 'redirect') { res.writeHead(302, { Location: 'https://example.invalid' }); res.end(); }
   else if (mode === 'malformed') res.end('{"schema_version":"2"}');
   else if (mode === 'oversized') res.end('x'.repeat(1048577));
   else if (mode === 'unavailable') { res.statusCode = 503; res.end('{}'); }
   else res.end(JSON.stringify(snapshot()));
  });
  upstream.listen(0, '127.0.0.1'); await once(upstream, 'listening');
  const web = createWebServer({ root: 'dist/web', config: { projectId: 'miragemesh', apiBasePath: '/api', engineEnabled: false, maxPreviewBytes: 1048576 }, projectId: 'miragemesh', engineAddress: `127.0.0.1:${upstream.address().port}` }); web.listen(0, '127.0.0.1'); await once(web, 'listening');
  try { const result = await fetch(`http://127.0.0.1:${web.address().port}/api/v1/certificates`); assert.equal(result.status, mode === 'valid' ? 200 : 503); assert.deepEqual(await result.json(), mode === 'valid' ? snapshot() : { error: 'certificate_status_unavailable' }); }
  finally { web.closeAllConnections(); upstream.closeAllConnections(); await Promise.all([new Promise(resolve => web.close(resolve)), new Promise(resolve => upstream.close(resolve))]); }
 }
});


test('published certificate schema and nanosecond overlap boundaries agree with engine semantics', () => {
 const spec = JSON.parse(readFileSync('contracts/openapi.v1.json', 'utf8'));
 const expand = value => !value || typeof value !== 'object' ? value : Array.isArray(value) ? value.map(expand) : value.$ref ? expand(spec.components.schemas[value.$ref.split('/').at(-1)]) : Object.fromEntries(Object.entries(value).map(([key, item]) => [key, expand(item)]));
 const ajv = new Ajv({ strict: true }); addFormats(ajv);
 const valid = ajv.compile(expand(spec.paths['/certificates'].get.responses['200'].content['application/json'].schema));
 const value = snapshot(); value.observed_at = '2026-01-01T00:59:59.999999999Z'; value.sensors[0].status = 'overlap'; value.sensors[0].recovery_available = false;
 assert.equal(valid(value), true, JSON.stringify(valid.errors)); assert.equal(validateCertificateSnapshot(value), value);
 value.observed_at = '2026-01-01T01:00:00Z'; assert.throws(() => validateCertificateSnapshot(value), /invalid/);
 value.sensors[0].status = 'current'; value.sensors[0].recovery_available = true; assert.equal(validateCertificateSnapshot(value), value);
 value.sensors[0].private_key = 'not permitted'; assert.equal(valid(value), false);
});
