import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { generateKeyPairSync } from 'node:crypto';
import { once } from 'node:events';
import http from 'node:http';

const config = { projectId: 'miragemesh', apiBasePath: '/api', engineEnabled: false, maxPreviewBytes: 1048576 };
const fixture = name => readFile(new URL(`../fixtures/miragemesh/C29/${name}.json`, import.meta.url), 'utf8').then(JSON.parse);

async function workspace(t) {
  const root = await mkdtemp(join(tmpdir(), 'miragemesh-readiness-'));
  await mkdir(join(root, 'web'), { recursive: true });
  await writeFile(join(root, 'web/index.html'), '<h1>synthetic workspace</h1>');
  t.after(() => rm(root, { recursive: true, force: true }));
  return { root: join(root, 'web'), base: root };
}

function validateContract(positive, negative, expected) {
  for (const value of [positive, negative, expected]) {
    if (value.fixture_version !== 1 || value.license !== 'Apache-2.0' || typeof value.provenance !== 'string' || value.provenance === '') throw new Error('invalid fixture metadata');
  }
  if (positive.schema_version !== 1 || positive.scope !== 'web-shell') throw new Error('invalid positive scope');
  if (!Array.isArray(positive.components) || positive.components.length !== 5) throw new Error('invalid component list');
  if (!Array.isArray(negative.cases) || negative.cases.length !== expected.negatives_unique) throw new Error('invalid negative count');
  if (negative.cases.some(item => !item.name || !item.expected_status)) throw new Error('invalid negative case');
  if (expected.diagnostics.keys.join(',') !== 'components,generated_at,limits,logs,schema_version,scope,status') throw new Error('invalid diagnostics keys');
  if (expected.logs.max_entries !== positive.limits.max_log_entries || expected.logs.max_bytes !== positive.limits.max_log_bytes) throw new Error('invalid log bounds');
}

async function listen(server) {
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  return server.address().port;
}

async function close(...servers) {
  for (const server of servers) server.closeAllConnections();
  await Promise.all(servers.map(server => new Promise(resolve => server.close(resolve))));
}

async function webServer(t, options) {
  const { createWebServer } = await import('../../scripts/serve-web.mjs');
  const space = await workspace(t);
  const server = createWebServer({ root: space.root, config, projectId: 'miragemesh', ...options });
  await listen(server);
  t.after(() => close(server));
  return { server, root: space.root, base: `http://127.0.0.1:${server.address().port}` };
}

const healthy = () => ({ statusCode: 200, body: JSON.stringify({ status: 'ok', scope: 'engine-runtime', version: '0.0.1', toolchain: 'go1.27.2', coreReady: false }) });
const emptySensors = () => ({ statusCode: 200, body: JSON.stringify({ schema_version: '1', offline_after_seconds: 300, sensors: [] }) });

test('C29 fixtures describe the readiness, redaction and bound contract', async () => {
  const [positive, negative, expected] = await Promise.all([fixture('positive'), fixture('negative'), fixture('expected-output')]);
  validateContract(positive, negative, expected);
  for (const mutation of [value => { value.fixture_version = 2; }, value => { value.license = 'unknown'; }, value => { value.provenance = ''; }]) {
    const copy = structuredClone(positive);
    mutation(copy);
    assert.throws(() => validateContract(copy, negative, expected));
  }
  const duplicate = structuredClone(negative);
  duplicate.cases.push({ ...duplicate.cases[0], name: duplicate.cases[0].name });
  assert.equal(new Set(duplicate.cases.map(item => item.name)).size, duplicate.cases.length - 1);

  const { redactDiagnosticMessage, createDiagnosticLog, readinessLimits } = await import('../../scripts/serve-web.mjs');
  const redacted = redactDiagnosticMessage('Authorization: Bearer SENTINEL_C29_TOKEN token=SENTINEL_C29_QUERY secret=SENTINEL_C29_SECRET');
  for (const sentinel of positive.sentinels) assert.doesNotMatch(redacted, new RegExp(sentinel));
  assert.match(redacted, /\[redacted\]/);
  assert.equal(redactDiagnosticMessage('x'.repeat(500)).length, positive.limits.max_message_chars);
  assert.deepEqual(readinessLimits, {
    probe_timeout_ms: positive.limits.probe_timeout_ms,
    max_log_entries: positive.limits.max_log_entries,
    max_log_bytes: positive.limits.max_log_bytes,
    max_message_chars: positive.limits.max_message_chars,
  });

  const ring = createDiagnosticLog({ probe_timeout_ms: 1500, max_log_entries: 2, max_log_bytes: 4096, max_message_chars: 256 });
  for (let index = 0; index < 5; index++) ring.add('error', 'engine_unavailable', `failure ${index}`);
  const snapshot = ring.snapshot();
  assert.equal(snapshot.entries.length, 2);
  assert.equal(snapshot.dropped, 3);
  assert.equal(snapshot.max_entries, 2);
});

test('real engine and authoritative store report ready, survive restart and reset diagnostics', async t => {
  const { startLocal } = await import('../../scripts/start-local.mjs');
  const options = await workspace(t);
  const { publicKey } = generateKeyPairSync('ed25519');
  const keyPath = join(options.base, 'operator-public.key');
  await writeFile(keyPath, publicKey.export({ format: 'der', type: 'spki' }).subarray(-32), { mode: 0o600 });
  const sensorStatus = {
    directory: join(options.base, 'sensor-state'), maxOperations: 32, maxBytes: 524288, maxManifestBytes: 32768,
    publicKeyPath: keyPath, maxSensors: 5,
    minHeartbeatSeconds: 5, maxHeartbeatSeconds: 3600,
    minSpoolLimitEvents: 1, maxSpoolLimitEvents: 12800,
    minEventBatchLimit: 1, maxEventBatchLimit: 12800,
  };
  for (let iteration = 0; iteration < 2; iteration++) {
    const running = await startLocal({ ...options, sensorStatus });
    t.after(() => running.close());
    const base = `http://127.0.0.1:${running.server.address().port}`;
    const ready = await fetch(base + '/readyz');
    assert.equal(ready.status, 200);
    const body = await ready.json();
    assert.equal(body.status, 'ready');
    assert.equal(body.scope, 'web-shell');
    assert.equal(body.engineReady, true);
    assert.equal(body.storageReady, true);
    assert.equal(body.providersReady, true);
    assert.deepEqual(body.components.map(component => component.name), ['web', 'engine', 'storage']);
    assert.ok(body.components.every(component => component.ready));
    const diagnostics = await fetch(base + '/api/diagnostics');
    assert.equal(diagnostics.status, 200);
    const proof = await diagnostics.json();
    assert.equal(proof.schema_version, 1);
    assert.equal(proof.status, 'ready');
    assert.deepEqual(proof.logs.entries, []);
    assert.equal(proof.logs.dropped, 0);
    assert.equal(proof.logs.max_entries, 32);
    assert.match(proof.generated_at, /^\d{4}-\d{2}-\d{2}T/);
    await running.close();
    assert.equal((await running.closed).exitCode, 0);
  }
});

test('failures are typed and visible, optional providers degrade, and sentinels never reach logs', async t => {
  const sentinels = ['SENTINEL_C29_SECRET', 'SENTINEL_C29_TOKEN', 'SENTINEL_C29_QUERY'];
  const mode = { engine: 'invalid' };
  const upstream = http.createServer((req, res) => {
    if (req.url === '/healthz') {
      const health = mode.engine === 'valid' ? healthy() : { statusCode: 200, body: JSON.stringify({ status: 'ok', token: sentinels[0] }) };
      res.statusCode = health.statusCode; res.end(health.body); return;
    }
    res.statusCode = 500;
    res.end(`credential=${sentinels[0]}`);
  });
  const port = await listen(upstream);
  t.after(() => close(upstream));
  const { base } = await webServer(t, {
    engineAddress: `127.0.0.1:${port}`,
    readiness: { storage: 'sensors', providers: ['certificates'], optionalProviders: ['updates'] },
  });
  const response = await fetch(base + '/readyz?token=' + sentinels[2], { headers: { Authorization: `Bearer ${sentinels[1]}` } });
  assert.equal(response.status, 503);
  const text = await response.text();
  const body = JSON.parse(text);
  assert.equal(body.status, 'not_ready');
  assert.equal(body.engineReady, false);
  assert.equal(body.storageReady, false);
  assert.equal(body.providersReady, false);
  const codes = Object.fromEntries(body.components.map(component => [component.name, component.code]));
  assert.deepEqual(codes, {
    web: null,
    engine: 'engine_unavailable',
    storage: 'storage_unavailable',
    'provider:certificates': 'provider_certificates_unavailable',
    'provider:updates': 'provider_updates_unavailable',
  });

  const diagnostics = await (await fetch(base + '/api/diagnostics')).json();
  assert.equal(diagnostics.status, 'not_ready');
  assert.ok(diagnostics.logs.entries.length > 0);
  const serialized = JSON.stringify(diagnostics);
  for (const sentinel of sentinels) assert.doesNotMatch(serialized, new RegExp(sentinel));
  for (const entry of diagnostics.logs.entries) assert.ok(entry.message.length <= diagnostics.logs.max_message_chars);
  assert.ok(diagnostics.logs.entries.some(entry => entry.level === 'warn' && entry.code === 'provider_updates_unavailable'));

  await fetch(base + '/readyz');
  const repeated = await (await fetch(base + '/api/diagnostics')).json();
  assert.equal(repeated.logs.entries.length, diagnostics.logs.entries.length);
  assert.equal(repeated.logs.dropped, 0);

  for (let index = 0; index < 40; index++) {
    mode.engine = mode.engine === 'invalid' ? 'valid' : 'invalid';
    await fetch(base + '/readyz');
  }
  const bounded = await (await fetch(base + '/api/diagnostics')).json();
  assert.ok(bounded.logs.entries.length <= 32);
  assert.ok(Buffer.byteLength(JSON.stringify(bounded.logs.entries)) <= bounded.logs.max_bytes);
  assert.ok(bounded.logs.dropped >= 8);
  assert.ok(bounded.logs.entries.every(entry => entry.code !== 'storage_unavailable' || entry.level === 'error'));
});

test('optional provider failure degrades while engine recovery returns to ready', async t => {
  const mode = { updates: 500, engine: 'invalid' };
  const upstream = http.createServer((req, res) => {
    if (req.url === '/healthz') {
      if (mode.engine === 'invalid') { res.statusCode = 200; res.end('{"status":"ok"}'); return; }
      const health = healthy(); res.statusCode = health.statusCode; res.end(health.body); return;
    }
    if (req.url === '/api/v1/updates') { res.statusCode = mode.updates; res.end(mode.updates === 500 ? '{"error":"update_status_unavailable"}' : '{}'); return; }
    if (req.url === '/api/v1/sensors') { const snapshot = emptySensors(); res.statusCode = snapshot.statusCode; res.end(snapshot.body); return; }
    res.statusCode = 404; res.end('{}');
  });
  const port = await listen(upstream);
  t.after(() => close(upstream));
  const optional = await webServer(t, { engineAddress: `127.0.0.1:${port}`, readiness: { optionalProviders: ['updates'] } });
  mode.engine = 'valid';
  let body = await (await fetch(optional.base + '/readyz')).json();
  assert.equal(body.status, 'degraded');
  assert.equal(body.engineReady, true);
  assert.equal(body.providersReady, false);

  mode.engine = 'invalid';
  const recovering = await webServer(t, { engineAddress: `127.0.0.1:${port}`, readiness: { storage: 'sensors' } });
  body = await (await fetch(recovering.base + '/readyz')).json();
  assert.equal(body.status, 'not_ready');
  mode.engine = 'valid';
  body = await (await fetch(recovering.base + '/readyz')).json();
  assert.equal(body.status, 'ready');
  const diagnostics = await (await fetch(recovering.base + '/api/diagnostics')).json();
  assert.ok(diagnostics.logs.entries.some(entry => entry.code === 'engine_unavailable'));
  assert.ok(diagnostics.logs.entries.some(entry => entry.code === 'component_recovered'));

  const { createWebServer } = await import('../../scripts/serve-web.mjs');
  const invalidRoot = (await workspace(t)).root;
  assert.throws(() => createWebServer({ root: invalidRoot, config, projectId: 'miragemesh', readiness: { storage: 'unknown' } }), /storage readiness surface/);
  assert.throws(() => createWebServer({ root: invalidRoot, config, projectId: 'miragemesh', readiness: { providers: ['podman'] } }), /readiness provider/);
});

test('standalone web shell reports web-only readiness and does not call an engine', async t => {
  const { base } = await webServer(t, {});
  const response = await fetch(base + '/readyz');
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.status, 'degraded');
  assert.equal(body.engineReady, false);
  assert.equal(body.storageReady, false);
  assert.equal(body.providersReady, true);
  assert.deepEqual(body.components.map(component => component.code), [null, 'not_configured', 'not_configured']);
  const diagnostics = await (await fetch(base + '/api/diagnostics')).json();
  assert.deepEqual(diagnostics.components.map(component => component.name), ['web', 'engine', 'storage']);
  assert.equal(diagnostics.components.find(component => component.name === 'engine').code, 'not_configured');
  assert.deepEqual(diagnostics.logs.entries, []);

  const source = await readFile(new URL('../../scripts/serve-web.mjs', import.meta.url), 'utf8');
  assert.match(source, /Invalid loopback engine address\./);
  const urls = source.match(/https?:\/\/[^\s"'`)]+/g) ?? [];
  for (const url of urls) assert.match(url, /^https?:\/\/(127\.0\.0\.1|localhost|\$\{[a-zA-Z]+\})/);
});

test('missing index makes the web component itself not ready', async t => {
  const { base, root } = await webServer(t, {});
  await rm(join(root, 'index.html'));
  const ready = await fetch(base + '/readyz');
  assert.equal(ready.status, 503);
  const body = await ready.json();
  assert.equal(body.status, 'not_ready');
  assert.deepEqual(body.components[0], { name: 'web', required: true, ready: false, code: 'web_assets_unavailable' });
  const diagnostics = await (await fetch(base + '/api/diagnostics')).json();
  assert.equal(diagnostics.status, 'not_ready');
  assert.ok(diagnostics.logs.entries.some(entry => entry.code === 'web_assets_unavailable'));
  assert.ok(diagnostics.logs.entries.length <= diagnostics.logs.max_entries);
});
