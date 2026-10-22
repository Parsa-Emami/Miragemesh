import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { once } from 'node:events';
import { readFileSync } from 'node:fs';
import Ajv from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import { validateIncidentSnapshot } from '../../apps/web/src/lib/incidents.mjs';
import { createWebServer } from '../../scripts/serve-web.mjs';

function snapshot() {
  const source = { sensor_id: 'sensor-22', event_id: 'event-01', sequence: 1, segment: 'segment-00000000000000000001', record: 1, digest: 'a'.repeat(64) };
  return { schema_version: '1', coverage: { complete: true, incomplete_segments: 0, missing_ordinals: [] }, unprojected_events: 0, rate_limit: 2, window_seconds: 60, incidents: [{ id: 'incident-' + 'b'.repeat(64), finding: { class: 'interaction', sensor_id: 'sensor-22', explanation: 'Synthetic observation.', sources: [structuredClone(source)] }, events: [{ source, event: { schema_version: '1', sensor_id: 'sensor-22', event_id: 'event-01', sequence: 1, observed_at: '2026-10-22T10:00:00Z', kind: 'http.request', metadata: { path: '/<img src=x onerror=globalThis.c22Sentinel=1>' } } }], history: [] }] };
}

test('published incident response schema validates sources and rejects missing trace fields', () => {
  const spec = JSON.parse(readFileSync(new URL('../../contracts/openapi.v1.json', import.meta.url), 'utf8'));
  function expand(value) {
    if (!value || typeof value !== 'object') return value;
    if (Array.isArray(value)) return value.map(expand);
    if (value.$ref) return expand(spec.components.schemas[value.$ref.split('/').at(-1)]);
    return Object.fromEntries(Object.entries(value).map(([key, field]) => [key, expand(field)]));
  }
  const ajv = new Ajv({ strict: true }); addFormats(ajv);
  const valid = ajv.compile(expand(spec.paths['/incidents'].get.responses['200'].content['application/json'].schema));
  assert.equal(valid(snapshot()), true, JSON.stringify(valid.errors));
  const missing = snapshot(); delete missing.incidents[0].events[0].source.digest;
  assert.equal(valid(missing), false);
});

test('incident boundary rejects broken source links and inconsistent coverage before rendering', () => {
  const value = snapshot();
  assert.equal(validateIncidentSnapshot(value), value);
  for (const mutate of [
    value => { value.schema_version = '2'; },
    value => { value.incidents[0].events[0].source.digest = 'forged'; },
    value => { value.incidents[0].events[0].source.segment = 'segment-' + '0'.repeat(20); },
    value => { value.incidents[0].events[0].event.sensor_id = 'other-sensor'; },
    value => { value.incidents[0].events[0].event.sequence = 2; },
    value => { value.incidents[0].finding.sources[0].record = 2; },
    value => { value.incidents[0].finding.class = 'sensor_health'; },
    value => { value.incidents[0].events[0].event.observed_at = 'yesterday'; },
    value => { value.incidents.push(structuredClone(value.incidents[0])); },
    value => { value.incidents[0].history.push({ status: 'x', reason: '', triaged_at: '2026-10-22T10:00:00Z' }); },
    value => { value.unprojected_events = 1; },
    value => { value.coverage.incomplete_segments = 1; },
    value => { value.rate_limit = Number.MAX_SAFE_INTEGER + 1; },
  ]) {
    const invalid = snapshot(); mutate(invalid); assert.throws(() => validateIncidentSnapshot(invalid), /invalid/);
  }
});

test('incident proxy rejects redirect, malformed, oversized and unavailable upstreams without egress', async () => {
  for (const mode of ['valid', 'redirect', 'malformed', 'oversized', 'unavailable']) {
    const upstream = http.createServer((req, res) => {
      assert.equal(req.url, '/api/v1/incidents'); assert.equal(req.method, 'GET');
      if (mode === 'redirect') { res.writeHead(302, { Location: 'https://example.invalid' }); res.end(); }
      else if (mode === 'oversized') res.end('x'.repeat(1048577));
      else if (mode === 'malformed') res.end('{"schema_version":"2"}');
      else if (mode === 'unavailable') { res.statusCode = 503; res.end('{"error":"incidents_unavailable"}'); }
      else res.end(JSON.stringify(snapshot()));
    });
    upstream.listen(0, '127.0.0.1'); await once(upstream, 'listening');
    const web = createWebServer({ root: 'dist/web', config: { projectId: 'miragemesh', apiBasePath: '/api', engineEnabled: false, maxPreviewBytes: 1048576 }, projectId: 'miragemesh', engineAddress: `127.0.0.1:${upstream.address().port}` });
    web.listen(0, '127.0.0.1'); await once(web, 'listening');
    try {
      const result = await fetch(`http://127.0.0.1:${web.address().port}/api/v1/incidents`);
      assert.equal(result.status, mode === 'valid' ? 200 : 503);
      assert.deepEqual(await result.json(), mode === 'valid' ? snapshot() : { error: 'incidents_unavailable' });
      const forbidden = await fetch(`http://127.0.0.1:${web.address().port}/api/v1/incidents/incident-${'a'.repeat(64)}/triage`, { method: 'POST', headers: { Origin: 'https://example.invalid', 'Content-Type': 'application/json' }, body: '{}' });
      assert.equal(forbidden.status, 403);
    } finally { web.closeAllConnections(); upstream.closeAllConnections(); await Promise.all([new Promise(resolve => web.close(resolve)), new Promise(resolve => upstream.close(resolve))]); }
  }
});
