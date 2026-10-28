import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync, execFileSync } from 'node:child_process';
import { cp, mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { once } from 'node:events';
import { verifyArtifact } from '../../scripts/verify-artifact.mjs';
import { verifySourceArchive } from '../../scripts/release-gate.mjs';

const repository = join(import.meta.dirname, '..', '..');
const fixtureRoot = join(repository, 'tests/fixtures/miragemesh/C31');
let work;
let first;
let second;

async function ensureBuild() {
  if (existsSync(join(repository, 'dist/web/index.html')) && existsSync(join(repository, 'dist/engine/miragemesh'))) return;
  execFileSync('npm', ['run', 'build'], { cwd: repository, stdio: 'inherit', timeout: 300000 });
}

async function packageInto(directory) {
  execFileSync(process.execPath, ['scripts/package-web.mjs', '--no-build', '--output', directory], {
    cwd: repository, encoding: 'utf8', timeout: 180000,
  });
  return directory;
}

async function listFiles(root) {
  const files = [];
  async function walk(directory, prefix = '') {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const name = prefix ? `${prefix}/${entry.name}` : entry.name;
      if (entry.isDirectory()) await walk(join(directory, entry.name), name);
      else files.push(name);
    }
  }
  await walk(root);
  return files.sort();
}

async function startArtifact(artifact, command = process.execPath, args = ['scripts/start-local.mjs', '--port', '0']) {
  const child = spawn(command, args, { cwd: artifact, detached: true, stdio: ['ignore', 'pipe', 'pipe'] });
  let output = '';
  let errors = '';
  child.stderr.on('data', chunk => { errors += chunk.toString('utf8'); });
  const ready = await new Promise((accept, reject) => {
    const timer = setTimeout(() => reject(new Error(`Artifact startup timed out: ${errors}`)), 20000);
    child.once('error', error => { clearTimeout(timer); reject(error); });
    child.once('exit', code => { clearTimeout(timer); reject(new Error(`Artifact exited during startup (${code}): ${errors}`)); });
    child.stdout.on('data', chunk => {
      output += chunk.toString('utf8');
      const line = output.split('\n')[0];
      if (!output.includes('\n')) return;
      try {
        const parsed = JSON.parse(line);
        clearTimeout(timer);
        accept(parsed);
      } catch { clearTimeout(timer); reject(new Error(`Invalid artifact startup output: ${line}`)); }
    });
  });
  return { child, ready, errors: () => errors };
}

async function stopArtifact(child) {
  if (child.exitCode !== null) return;
  try { process.kill(-child.pid, 'SIGTERM'); } catch { child.kill('SIGTERM'); }
  await Promise.race([once(child, 'exit'), new Promise(resolve => setTimeout(resolve, 10000))]);
  if (child.exitCode === null) {
    try { process.kill(-child.pid, 'SIGKILL'); } catch { child.kill('SIGKILL'); }
    await once(child, 'exit').catch(() => {});
  }
}

before(async () => {
  await ensureBuild();
  work = await mkdtemp(join(tmpdir(), 'miragemesh-artifact-'));
  first = await packageInto(join(work, 'miragemesh-0.0.1-linux-amd64'));
  second = await packageInto(join(work, 'second', 'miragemesh-0.0.1-linux-amd64'));
});

after(async () => { if (work) await rm(work, { recursive: true, force: true }); });

test('complete artifact verifies its engine, web, offline resources, source, SBOM, notices and provenance', async () => {
  const fixtures = JSON.parse(await readFile(join(fixtureRoot, 'positive.json'), 'utf8'));
  const result = await verifyArtifact(first);
  assert.deepEqual(result.errors, []);
  assert.equal(result.passed, true);
  for (const path of fixtures.required_paths) assert.equal(existsSync(join(first, ...path.split('/'))), true, `missing ${path}`);
  const policy = JSON.parse(await readFile(join(repository, 'tests/fixtures/miragemesh/C38/positive.json'), 'utf8'));
  for (const path of policy.policies) {
    assert.deepEqual(await readFile(join(first, path)), await readFile(join(repository, path)), `stale shipped policy: ${path}`);
  }
  const provenance = JSON.parse(await readFile(join(first, 'provenance.json'), 'utf8'));
  assert.equal(provenance.build.complete_product, true);
  assert.equal(provenance.build.web_only, false);
  assert.ok(provenance.source.archive.files > 400);
  assert.match(provenance.source.source_identity, /^sha256:[0-9a-f]{64}$/);
  const sbom = JSON.parse(await readFile(join(first, 'sbom.cdx.json'), 'utf8'));
  assert.equal(sbom.bomFormat, 'CycloneDX');
  assert.equal(sbom.specVersion, fixtures.sbom_spec_version);
  for (const name of fixtures.sbom_components) {
    assert.ok([sbom.metadata.component.name, ...sbom.components.map(component => component.name)].map(value => value.toLowerCase()).includes(name), `SBOM missing ${name}`);
  }
  for (const component of sbom.components) assert.ok(component.licenses?.length > 0, `license missing for ${component.name}`);
  const offline = JSON.parse(await readFile(join(first, 'offline/resources.json'), 'utf8'));
  assert.equal(offline.network_egress_required, false);
  assert.deepEqual(offline.rules, []);
  assert.deepEqual(offline.grammars, []);
  assert.ok(offline.resources.length >= 10);
  const version = spawnSync(join(first, 'dist/engine/miragemesh'), ['--version'], { encoding: 'utf8', timeout: 30000 });
  assert.equal(version.status, 0);
  const parsed = JSON.parse(version.stdout);
  assert.deepEqual({ status: parsed.status, version: parsed.version, coreReady: parsed.coreReady }, fixtures.engine_version);
  assert.equal(((await stat(join(first, 'dist/engine/miragemesh'))).mode & 0o111) !== 0, true);
});

test('two builds from one source and toolchain are byte-identical', async () => {
  const left = await listFiles(first);
  const right = await listFiles(second);
  assert.deepEqual(left, right);
  for (const name of left) {
    const a = await readFile(join(first, ...name.split('/')));
    const b = await readFile(join(second, ...name.split('/')));
    assert.deepEqual(a, b, `non-reproducible file: ${name}`);
  }
});

test('C39 refuses a packaged source archive with different bytes even under unchanged provenance', async () => {
  const inventory = await verifySourceArchive(repository, first);
  assert.ok(Object.keys(inventory).length > 400);
  const changed = join(work, 'c39-changed', 'miragemesh-0.0.1-linux-amd64');
  await cp(first, changed, { recursive: true });
  const temporary = join(work, 'c39-source');
  await import('node:fs/promises').then(({ mkdir }) => mkdir(temporary));
  const archive = join(changed, 'source/miragemesh-0.0.1-source.tar.gz');
  execFileSync('tar', ['-xzf', archive, '-C', temporary]);
  await writeFile(join(temporary, 'miragemesh-0.0.1/README.md'), 'C39 altered source archive bytes');
  execFileSync('tar', ['-czf', archive, '-C', temporary, 'miragemesh-0.0.1']);
  await assert.rejects(verifySourceArchive(repository, changed), { code: 'wrong_source' });
});

test('packaged runtime starts in isolation and exposes only supported local surfaces', async () => {
  const artifact = await startArtifact(first);
  try {
    const base = `http://127.0.0.1:${artifact.ready.port}`;
    const health = await fetch(`${base}/healthz`);
    assert.equal(health.status, 200);
    const readyz = await fetch(`${base}/readyz`);
    assert.equal(readyz.status, 200);
    const engine = await fetch(`${base}/api/engine/health`);
    assert.equal(engine.status, 200);
    const engineHealth = await engine.json();
    assert.equal(engineHealth.status, 'ok');
    assert.equal(engineHealth.scope, 'engine-runtime');
    assert.equal(engineHealth.coreReady, false);
    assert.equal(engineHealth.version, '0.0.1');
    const certificates = await fetch(`${base}/api/v1/certificates`);
    assert.equal(certificates.status, 503);
    assert.deepEqual(await certificates.json(), { error: 'certificate_status_unavailable' });
  } finally { await stopArtifact(artifact.child); }
});

test('runtime makes no internet connection by default', { skip: !existsSync('/usr/bin/strace') && 'strace is unavailable' }, async () => {
  const trace = join(work, 'connect.trace');
  const artifact = await startArtifact(first, '/usr/bin/strace', ['-f', '-e', 'trace=connect', '-o', trace, process.execPath, 'scripts/start-local.mjs', '--port', '0']);
  try {
    const health = await fetch(`http://127.0.0.1:${artifact.ready.port}/healthz`);
    assert.equal(health.status, 200);
    await fetch(`http://127.0.0.1:${artifact.ready.port}/readyz`);
  } finally { await stopArtifact(artifact.child); }
  const lines = (await readFile(trace, 'utf8')).split('\n').filter(line => line.includes('connect('));
  assert.ok(lines.length > 0, 'No connect calls were traced.');
  const inet = lines.filter(line => line.includes('AF_INET'));
  assert.ok(inet.length > 0, 'No internet-family connect calls were observed.');
  for (const line of inet) {
    assert.ok(line.includes('127.0.0.1') || line.includes('"::1"'), `Artifact attempted a non-loopback connection: ${line}`);
  }
});

test('negative artifact mutations fail with the recorded error semantics', async () => {
  const cases = JSON.parse(await readFile(join(fixtureRoot, 'negative.json'), 'utf8')).cases;
  const mutations = {
    'missing-engine': async root => { await rm(join(root, 'dist/engine/miragemesh')); },
    'missing-sbom': async root => { await rm(join(root, 'sbom.cdx.json')); },
    'missing-source-archive': async root => { await rm(join(root, 'source/miragemesh-0.0.1-source.tar.gz')); },
    'missing-notice': async root => { await rm(join(root, 'NOTICE')); },
    'checksum-mismatch': async root => { await writeFile(join(root, 'README.md'), 'modified\n', { flag: 'a' }); },
    'web-only-artifact': async root => {
      await rm(join(root, 'dist/engine/miragemesh'));
      await rm(join(root, 'source'), { recursive: true, force: true });
    },
    'forbidden-private-material': async root => { await writeFile(join(root, '.env'), 'SYNTHETIC=not-a-secret\n'); },
    'unsafe-checksum-path': async root => { await writeFile(join(root, 'SHA256SUMS.txt'), `${'0'.repeat(64)}  ../escape\n`, { flag: 'a' }); },
    'duplicate-checksum-entry': async root => {
      const sums = await readFile(join(root, 'SHA256SUMS.txt'), 'utf8');
      await writeFile(join(root, 'SHA256SUMS.txt'), sums + sums.split('\n')[0] + '\n');
    },
    'incomplete-checksum-coverage': async root => {
      const sums = (await readFile(join(root, 'SHA256SUMS.txt'), 'utf8')).split('\n').filter(Boolean);
      await writeFile(join(root, 'SHA256SUMS.txt'), sums.slice(1).join('\n') + '\n');
    },
  };
  assert.deepEqual(Object.keys(mutations).sort(), cases.map(item => item.name).sort());
  for (const item of cases) {
    const root = join(work, 'negative', item.name, 'miragemesh-0.0.1-linux-amd64');
    await cp(first, root, { recursive: true });
    await mutations[item.name](root);
    const result = await verifyArtifact(root);
    assert.equal(result.passed, false, `${item.name} unexpectedly passed`);
    assert.ok(result.errors.some(error => error.code === item.expected), `${item.name}: expected ${item.expected}, got ${JSON.stringify(result.errors)}`);
  }
});
