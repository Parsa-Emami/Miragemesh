import test from 'node:test';
import assert from 'node:assert/strict';
import { access, mkdtemp, mkdir, writeFile, rm, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import http from 'node:http';
import { once } from 'node:events';
import { spawn } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';

const config = { projectId: 'miragemesh', apiBasePath: '/api', engineEnabled: false, maxPreviewBytes: 1048576 };
async function workspace(t) {
  const root = await mkdtemp(join(tmpdir(), 'miragemesh-launch-'));
  await mkdir(join(root, 'web'));
  await writeFile(join(root, 'web/index.html'), '<h1>synthetic workspace</h1>');
  await writeFile(join(root, 'config.json'), JSON.stringify(config));
  t.after(() => rm(root, { recursive: true, force: true }));
  return { root: join(root, 'web'), configPath: join(root, 'config.json'), port: 0 };
}

test('real launcher serves engine health, preserves disabled admission, stops and restarts', async t => {
  await assert.doesNotReject(access(new URL('../../scripts/start-local.mjs', import.meta.url)), 'C03 launcher must exist');
  const { startLocal } = await import('../../scripts/start-local.mjs');
  const options = await workspace(t);
  for (let iteration = 0; iteration < 2; iteration++) {
    const running = await startLocal(options);
    t.after(() => running.close());
    const base = `http://127.0.0.1:${running.server.address().port}`;
    const health = await (await fetch(base + '/api/engine/health')).json();
    assert.deepEqual(health, { status: 'ok', scope: 'engine-runtime', version: '0.0.1', toolchain: 'go1.27.2', coreReady: false });
    assert.equal((await fetch(base + '/api/v1/unimplemented')).status, 503);
    assert.equal((await fetch(base + '/api/engine/health', { method: 'POST' })).status, 405);
    assert.equal((await (await fetch(base + '/runtime-config.json')).json()).engineEnabled, false);
    assert.equal((await (await fetch(base + '/readyz')).json()).engineReady, false);
    await running.close();
    assert.equal((await running.closed).exitCode, 0);
    assert.throws(() => process.kill(running.child.pid, 0), /ESRCH/);
    await assert.rejects(fetch(base + '/healthz'));
  }
});

test('engine crash stops the web listener with a failing outcome', async t => {
  const { startLocal } = await import('../../scripts/start-local.mjs');
  const running = await startLocal(await workspace(t));
  t.after(() => running.close());
  const base = `http://127.0.0.1:${running.server.address().port}`;
  running.child.kill('SIGKILL');
  assert.equal((await running.closed).exitCode, 1);
  await assert.rejects(fetch(base + '/healthz'));
});

test('occupied web port remains owned by its server and launch cleans up its engine', async t => {
  const { startLocal } = await import('../../scripts/start-local.mjs');
  const occupant = http.createServer((req, res) => res.end('unrelated service'));
  occupant.listen(0, '127.0.0.1'); await once(occupant, 'listening');
  t.after(() => new Promise(resolve => occupant.close(resolve)));
  await assert.rejects(startLocal({ ...await workspace(t), port: occupant.address().port }), /EADDRINUSE/);
  assert.equal(await (await fetch(`http://127.0.0.1:${occupant.address().port}`)).text(), 'unrelated service');
});

test('missing engine and invalid configuration fail before a successful launch', async t => {
  const { startLocal } = await import('../../scripts/start-local.mjs');
  const options = await workspace(t);
  await assert.rejects(startLocal({ ...options, engineBinary: '/no-such-miragemesh-engine' }), /ENOENT/);
  await writeFile(options.configPath, '{');
  await assert.rejects(startLocal(options), /JSON/);
  await assert.rejects(startLocal({ ...options, host: '0.0.0.0' }), /loopback/);
});

test('health boundary rejects malformed, oversized, redirected, unavailable and stalled upstreams', async t => {
  const { createWebServer } = await import('../../scripts/serve-web.mjs');
  const options = await workspace(t);
  for (const mode of ['invalid', 'oversized', 'redirect', 'unavailable', 'stalled']) {
    const upstream = http.createServer((req, res) => {
      if (mode === 'stalled') return;
      if (mode === 'redirect') { res.writeHead(302, { Location: 'http://example.invalid' }); res.end(); }
      else if (mode === 'oversized') res.end('x'.repeat(5000));
      else { res.statusCode = mode === 'unavailable' ? 503 : 200; res.end('{"status":"ok","coreReady":true}'); }
    });
    upstream.listen(0, '127.0.0.1'); await once(upstream, 'listening');
    const web = createWebServer({ root: options.root, config, projectId: 'miragemesh', engineAddress: `127.0.0.1:${upstream.address().port}` });
    web.listen(0, '127.0.0.1'); await once(web, 'listening');
    try { assert.equal((await fetch(`http://127.0.0.1:${web.address().port}/api/engine/health`)).status, 503, mode); }
    finally { web.closeAllConnections(); upstream.closeAllConnections(); await Promise.all([new Promise(r => web.close(r)), new Promise(r => upstream.close(r))]); }
  }
});

test('synthetic C03 fixtures are versioned and cannot claim product readiness', async () => {
  const { validateHealth } = await import('../../apps/web/src/lib/runtime-config.mjs');
  const read = async name => JSON.parse(await readFile(new URL(`../fixtures/miragemesh/C03/${name}.json`, import.meta.url)));
  const positive = await read('positive');
  assert.equal(positive.license, 'Apache-2.0'); assert.ok(positive.provenance);
  assert.equal(positive.schema_version, 1);
  assert.deepEqual(validateHealth(positive.health), (await read('expected-output')).health);
  const invalid = await read('invalid');
  assert.throws(() => validateHealth(invalid.health));
});

async function cli(t, options) {
  const child = spawn(process.execPath, ['scripts/start-local.mjs', '--port', '0', '--root', options.root, '--config', options.configPath], { stdio: ['ignore', 'pipe', 'pipe'] });
  const exit = once(child, 'exit');
  t.after(async () => { if (child.exitCode === null && child.signalCode === null) { child.kill('SIGTERM'); await exit; } });
  const ready = await new Promise((accept, reject) => {
    const deadline = setTimeout(() => reject(new Error('CLI startup timed out')), 5000);
    child.once('error', reject);
    let bytes = '';
    child.stdout.on('data', data => { bytes += data; if (bytes.includes('\n')) { clearTimeout(deadline); try { accept(JSON.parse(bytes.split('\n')[0])); } catch (error) { reject(error); } } });
    exit.then(() => { clearTimeout(deadline); reject(new Error('CLI exited before startup')); });
  });
  return { child, ready, exit };
}

test('CLI SIGINT and SIGTERM release both listeners; supervisor death closes engine stdin', async t => {
  const options = await workspace(t);
  for (const signal of ['SIGINT', 'SIGTERM', 'SIGKILL']) {
    const running = await cli(t, options);
    const engine = `http://${running.ready.engineAddress}/healthz`;
    assert.equal((await fetch(engine)).status, 200);
    running.child.kill(signal);
    const [code] = await running.exit;
    if (signal !== 'SIGKILL') assert.equal(code, 0);
    await assert.rejects(fetch(`http://127.0.0.1:${running.ready.port}/healthz`));
    let stopped = false;
    for (let attempt = 0; attempt < 50; attempt++) {
      try { await fetch(engine); await delay(20); } catch { stopped = true; break; }
    }
    assert.equal(stopped, true, 'engine listener survived supervisor exit');
  }
});

test('unresponsive startup times out and cancellation terminates only the owned child', { timeout: 20000 }, async t => {
  const { startLocal } = await import('../../scripts/start-local.mjs');
  const options = await workspace(t);
  const fixture = join(options.root, 'stalled-engine');
  const pidPath = join(options.root, 'pid');
  await writeFile(fixture, `#!${process.execPath}\nimport fs from 'node:fs'; fs.writeFileSync(${JSON.stringify(pidPath)}, String(process.pid)); process.stdin.resume();`, { mode: 0o700 });
  const start = Date.now();
  await assert.rejects(startLocal({ ...options, engineBinary: fixture }), /deadline/);
  assert.ok(Date.now() - start < 13000);
  const expiredPid = Number(await readFile(pidPath, 'utf8'));
  assert.throws(() => process.kill(expiredPid, 0), /ESRCH/);
  await rm(pidPath);
  const controller = new AbortController();
  const pending = startLocal({ ...options, engineBinary: fixture, signal: controller.signal });
  // Observe the real child before cancelling; do not rely on scheduler timing.
  let pid;
  for (let attempt = 0; attempt < 100; attempt++) {
    try { pid = Number(await readFile(pidPath, 'utf8')); break; } catch { await delay(10); }
  }
  assert.ok(pid);
  controller.abort();
  await assert.rejects(pending, /cancelled|exited/);
  assert.throws(() => process.kill(pid, 0), /ESRCH/);
});

test('failed Go compilation preserves the previous binary and removes staging output', async t => {
  const { buildEngine } = await import('../../scripts/build-engine.mjs');
  const root = await mkdtemp(join(tmpdir(), 'miragemesh-build-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(join(root, 'dist/engine'), { recursive: true });
  await mkdir(join(root, 'cmd/miragemesh'), { recursive: true });
  await writeFile(join(root, 'go.mod'), 'module example.invalid/synthetic\n\ngo 1.27.2\n');
  await writeFile(join(root, 'cmd/miragemesh/main.go'), 'package main\nfunc main() { missing() }\n');
  const previous = join(root, 'dist/engine/miragemesh');
  await writeFile(previous, 'last valid artifact');
  assert.throws(() => buildEngine(root), /previous binary preserved/);
  assert.equal(await readFile(previous, 'utf8'), 'last valid artifact');
  const { readdir } = await import('node:fs/promises');
  assert.deepEqual(await readdir(join(root, 'dist/engine')), ['miragemesh']);
});

test('startup rejects forged non-loopback handshakes and unsafe health destinations', async t => {
  const { startLocal } = await import('../../scripts/start-local.mjs');
  const { readEngineHealth } = await import('../../scripts/serve-web.mjs');
  for (const address of ['example.invalid:80', '0.0.0.0:80', '127.0.0.1:65536', '127.0.0.1:80@outside.invalid']) await assert.rejects(readEngineHealth(address), /loopback/);
  const options = await workspace(t);
  const engineBinary = join(options.root, 'forged-engine');
  await writeFile(engineBinary, `#!${process.execPath}\nconsole.log(JSON.stringify({service:'miragemesh-engine', pid:process.pid, address:'example.invalid:80'})); process.stdin.resume();`, { mode: 0o700 });
  await assert.rejects(startLocal({ ...options, engineBinary }), /Invalid engine startup/);
});
