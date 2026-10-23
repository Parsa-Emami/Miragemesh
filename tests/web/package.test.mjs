import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { cp, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { once } from 'node:events';

test('web package starts from an isolated directory with every server validator dependency', async () => {
 execFileSync(process.execPath, ['scripts/package-web.mjs'], { encoding: 'utf8', timeout: 15000 });
 const dir = await mkdtemp(join(tmpdir(), 'miragemesh-web-package-'));
 let server;
 try {
  await cp('dist/release', dir, { recursive: true });
  const { createWebServer } = await import(pathToFileURL(join(dir, 'scripts', 'serve-web.mjs')).href);
  server = createWebServer({ root: join(dir, 'web'), config: { projectId: 'miragemesh', apiBasePath: '/api', engineEnabled: false, maxPreviewBytes: 1048576 }, projectId: 'miragemesh' });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const result = await fetch(`http://127.0.0.1:${server.address().port}/api/v1/certificates`);
  assert.equal(result.status, 503); assert.deepEqual(await result.json(), { error: 'certificate_status_unavailable' });
 } finally { if (server) { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); } await rm(dir, { recursive: true, force: true }); }
});
