import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { mkdtemp, mkdir, writeFile, rm, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { once } from 'node:events';
import { createWebServer, readEngineHealth, readEngineSensors, readEngineCertificates, readEngineUpdates, requestEngineIncidents } from '../../scripts/serve-web.mjs';

const config = { projectId: 'miragemesh', apiBasePath: '/api', engineEnabled: false, maxPreviewBytes: 1048576 };

async function workspace(t) {
  const dir = await mkdtemp(join(tmpdir(), 'c32-network-'));
  const root = join(dir, 'public');
  await mkdir(join(root, 'assets'), { recursive: true });
  await writeFile(join(root, 'index.html'), '<!doctype html><h1>MirageMesh Local</h1>');
  await writeFile(join(root, 'assets', 'chunk-a1b2c3d4.js'), 'export const loaded = true;');
  t.after(async () => {
    await rm(dir, { recursive: true, force: true });
  });
  return { dir, root };
}

async function listen(server) {
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  return server.address().port;
}

async function close(...servers) {
  for (const server of servers) {
    if (server) {
      server.closeAllConnections();
      await new Promise(resolve => server.close(resolve));
    }
  }
}

test('C32 fixtures validate contract, schema bounds and negative catalog', async () => {
  const positive = JSON.parse(await readFile(new URL('../fixtures/miragemesh/C32/positive.json', import.meta.url), 'utf8'));
  const negative = JSON.parse(await readFile(new URL('../fixtures/miragemesh/C32/negative.json', import.meta.url), 'utf8'));
  const expected = JSON.parse(await readFile(new URL('../fixtures/miragemesh/C32/expected-output.json', import.meta.url), 'utf8'));

  assert.equal(positive.fixture_version, 1);
  assert.equal(positive.license, 'Apache-2.0');
  assert.equal(positive.ingress.public_domain_required, false);
  assert.deepEqual(positive.loopback.hosts, ['127.0.0.1', 'localhost', '[::1]']);

  assert.equal(negative.fixture_version, 1);
  assert.equal(negative.license, 'Apache-2.0');
  assert.ok(Array.isArray(negative.cases) && negative.cases.length >= 10);

  assert.equal(expected.fixture_version, 1);
  assert.equal(expected.license, 'Apache-2.0');
  assert.equal(expected.public_domain_required, false);
  assert.equal(expected.loopback_enforced, true);
});

test('local web server rejects foreign Host, spoofed Host, and cross-origin requests', async t => {
  const { root } = await workspace(t);
  const server = createWebServer({ root, config, projectId: 'miragemesh' });
  const port = await listen(server);
  t.after(() => close(server));

  const validAuthority = `127.0.0.1:${port}`;
  const negative = JSON.parse(await readFile(new URL('../fixtures/miragemesh/C32/negative.json', import.meta.url), 'utf8'));

  // Test cases matching the negative fixture
  for (const testCase of negative.cases.filter(c => c.headers)) {
    const response = await new Promise((resolve, reject) => {
      const headers = { ...testCase.headers };
      if (!headers.Host) headers.Host = validAuthority;
      const req = http.request(`http://${validAuthority}${testCase.path}`, { method: 'GET', headers }, res => {
        let body = '';
        res.on('data', chunk => { body += chunk; });
        res.on('end', () => resolve({ status: res.statusCode, body }));
      });
      req.on('error', reject);
      req.end();
    });

    assert.equal(response.status, testCase.expected_status, `case ${testCase.name} should yield status ${testCase.expected_status}`);
    const parsed = JSON.parse(response.body);
    assert.equal(parsed.error, testCase.expected_error);
  }

  // Test legitimate loopback Host and Origin
  const validRes = await fetch(`http://${validAuthority}/healthz`, {
    headers: { Host: validAuthority, Origin: `http://${validAuthority}` }
  });
  assert.equal(validRes.status, 200);
  assert.deepEqual(await validRes.json(), { status: 'ok', scope: 'web-shell' });
});

test('cache-control and security headers are strictly enforced across static and dynamic routes', async t => {
  const { root } = await workspace(t);
  const server = createWebServer({ root, config, projectId: 'miragemesh' });
  const port = await listen(server);
  t.after(() => close(server));

  const base = `http://127.0.0.1:${port}`;

  // Dynamic routes must be no-store
  for (const path of ['/', '/index.html', '/healthz', '/readyz', '/runtime-config.json', '/api/diagnostics']) {
    const res = await fetch(base + path);
    assert.equal(res.status, 200, `path ${path} should be 200`);
    assert.equal(res.headers.get('cache-control'), 'no-store', `path ${path} must have Cache-Control: no-store`);
    assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(res.headers.get('x-frame-options'), 'DENY');
    assert.equal(res.headers.get('referrer-policy'), 'no-referrer');
    assert.match(res.headers.get('content-security-policy'), /frame-ancestors 'none'/);
  }

  // Fingerprinted asset route must be immutable public cache
  const assetRes = await fetch(base + '/assets/chunk-a1b2c3d4.js');
  assert.equal(assetRes.status, 200);
  assert.equal(assetRes.headers.get('cache-control'), 'public, max-age=31536000, immutable');
  assert.equal(assetRes.headers.get('x-content-type-options'), 'nosniff');
});

test('path confinement rejects path traversal and forbidden directory escapes', async t => {
  const { root } = await workspace(t);
  const server = createWebServer({ root, config, projectId: 'miragemesh' });
  const port = await listen(server);
  t.after(() => close(server));

  const base = `http://127.0.0.1:${port}`;

  const { Socket } = await import('node:net');
  for (const path of [
    '/assets/../../package.json',
    '/assets/%2e%2e/%2e%2e/package.json',
    '/..%5c..%5cpackage.json',
    '/assets/%00test.js',
    '/%ZZ'
  ]) {
    const res = await new Promise((resolve, reject) => {
      const client = new Socket();
      client.connect(port, '127.0.0.1', () => {
        client.write(`GET ${path} HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nConnection: close\r\n\r\n`);
      });
      let responseData = '';
      client.on('data', chunk => { responseData += chunk.toString('utf8'); });
      client.on('end', () => {
        const [headerPart, ...bodyParts] = responseData.split('\r\n\r\n');
        const statusLine = headerPart.split('\r\n')[0];
        const status = Number(statusLine.split(' ')[1]);
        resolve({ status, body: bodyParts.join('\r\n\r\n') });
      });
      client.on('error', reject);
    });
    assert.equal(res.status, 400, `path traversal ${path} must yield 400`);
    assert.deepEqual(JSON.parse(res.body), { error: 'invalid_path' });
  }
});

test('engine address validation strictly confines engine calls to valid loopback addresses', async () => {
  const invalidAddresses = [
    '0.0.0.0:8080',
    '192.168.1.1:8080',
    'example.invalid:80',
    '10.0.0.1:4000',
    '127.0.0.1:70000',
    '127.0.0.1:-1',
    'not-an-address'
  ];

  for (const addr of invalidAddresses) {
    await assert.rejects(readEngineHealth(addr), /Invalid loopback engine address/);
    await assert.rejects(readEngineSensors(addr), /Invalid loopback engine address/);
    await assert.rejects(readEngineCertificates(addr), /Invalid loopback engine address/);
    await assert.rejects(readEngineUpdates(addr), /Invalid loopback engine address/);
    await assert.rejects(requestEngineIncidents(addr), /Invalid local incident request/);
  }
});

test('optional private reverse proxy allowedHosts configuration allows documented private ingress', async t => {
  const { root } = await workspace(t);
  const server = createWebServer({
    root,
    config,
    projectId: 'miragemesh',
    allowedHosts: ['miragemesh.internal', 'dashboard.private.lan']
  });
  const port = await listen(server);
  t.after(() => close(server));

  // Request with configured private host
  const res = await new Promise((resolve, reject) => {
    const req = http.request(`http://127.0.0.1:${port}/healthz`, {
      method: 'GET',
      headers: {
        Host: `miragemesh.internal:${port}`,
        Origin: `https://miragemesh.internal:${port}`
      }
    }, res => {
      let body = '';
      res.on('data', chunk => { body += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, body }));
    });
    req.on('error', reject);
    req.end();
  });

  assert.equal(res.status, 200);
  assert.deepEqual(JSON.parse(res.body), { status: 'ok', scope: 'web-shell' });

  // Unconfigured foreign host is still rejected
  const rejected = await new Promise((resolve, reject) => {
    const req = http.request(`http://127.0.0.1:${port}/healthz`, {
      method: 'GET',
      headers: {
        Host: `unauthorized.internal:${port}`
      }
    }, res => {
      let body = '';
      res.on('data', chunk => { body += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, body }));
    });
    req.on('error', reject);
    req.end();
  });

  assert.equal(rejected.status, 403);
  assert.deepEqual(JSON.parse(rejected.body), { error: 'forbidden_origin' });
});
