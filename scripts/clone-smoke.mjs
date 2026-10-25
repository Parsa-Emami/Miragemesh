import { spawn, spawnSync } from 'node:child_process';
import { mkdtemp, mkdir, rm, writeFile, readFile, readdir } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isDeepStrictEqual } from 'node:util';
import { goEnvironment } from './oss-bootstrap.mjs';
import { startLocal } from './start-local.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const temp = await mkdtemp(join(tmpdir(), 'oss-clone-'));
let server;
let seededServer;

function freePort() {
  return new Promise((accept, reject) => {
    const probe = createServer();
    probe.once('error', reject);
    probe.listen(0, '127.0.0.1', () => {
      const { port } = probe.address();
      probe.close(error => error ? reject(error) : accept(port));
    });
  });
}

async function segmentBytes(directory) {
  const names = (await readdir(directory)).filter(name => name.endsWith('.jsonl')).sort();
  return Object.fromEntries(await Promise.all(names.map(async name => [name, await readFile(join(directory, name), 'utf8')])));
}

function run(command, args, cwd, options = {}) {
  const result = spawnSync(command, args, {
    cwd, encoding: 'utf8', maxBuffer: 8 * 1024 * 1024, ...options,
  });
  if (result.status !== 0) {
    throw new Error(`${command} failed: ${result.stdout ?? ''}${result.stderr ?? result.error?.message ?? ''}`);
  }
  return result.stdout.trim();
}

try {
  // Test the index so contributors can verify a proposed commit before pushing.
  const tree = run('git', ['write-tree'], root);
  const identity = {
    ...process.env,
    GIT_AUTHOR_NAME: 'Clone smoke', GIT_AUTHOR_EMAIL: 'clone@example.invalid',
    GIT_COMMITTER_NAME: 'Clone smoke', GIT_COMMITTER_EMAIL: 'clone@example.invalid',
  };
  const commit = run('git', ['commit-tree', tree, '-p', 'HEAD', '-m', 'temporary staged source proof'], root, { env: identity });

  // Advertise the snapshot from an isolated repository. No source refs change;
  // a real transport clone collects the snapshot and its available ancestry.
  const source = join(temp, 'source.git');
  run('git', ['init', '--bare', '--quiet', source], temp);
  const objects = resolve(root, run('git', ['rev-parse', '--git-path', 'objects'], root));
  await mkdir(join(source, 'objects', 'info'), { recursive: true });
  await writeFile(join(source, 'objects', 'info', 'alternates'), objects + '\n');
  run('git', ['--git-dir=' + source, 'update-ref', 'refs/heads/snapshot', commit], temp);
  const checkout = join(temp, 'checkout');
  run('git', ['clone', '--quiet', '--no-local', '--branch', 'snapshot', source, checkout], temp);
  if (run('git', ['rev-parse', 'HEAD^{tree}'], checkout) !== tree) throw new Error('Cloned tree differs from index');
  // Preserve ancestry so historical proof is checked at its actual recorded source.
  console.log(run('python3', ['scripts/verify_ci_source.py'], checkout));
  if (!process.env.npm_execpath) throw new Error('Invoke through npm run test:clone.');
  run(process.execPath, [process.env.npm_execpath, 'run', 'setup'], checkout);
  await mkdir(join(checkout, 'dist/ci'), { recursive: true });
  run('go', ['vet', './...'], checkout, { env: goEnvironment });
  const engineTests = run('go', ['test', '-race', '-count=1', '-json', './...'], checkout, { env: goEnvironment });
  await writeFile(join(checkout, 'dist/ci/engine-tests.jsonl'), engineTests + '\n');
  console.log(run(process.execPath, ['scripts/verify-engine-tests.mjs', 'dist/ci/engine-tests.jsonl'], checkout));

  // C30: run the real reference workflow in the clone, then prove readiness,
  // restart/restore and the browser workflow against that accepted state.
  const c30 = join(temp, 'c30');
  run('go', ['run', './tests/fixtures/miragemesh/C30/seed', c30], checkout, { env: goEnvironment, timeout: 120000 });
  const outcome = JSON.parse(await readFile(join(c30, 'outcome.json'), 'utf8'));
  const c30Expected = JSON.parse(await readFile(join(checkout, 'tests/fixtures/miragemesh/C30/expected-output.json'), 'utf8'));
  const scenario = JSON.parse(await readFile(join(checkout, 'tests/scenarios/clone-to-value.json'), 'utf8'));
  if (!isDeepStrictEqual(outcome.steps.map(step => step.name), scenario.steps.map(step => step.id))) throw new Error('C30 steps differ from the scenario');
  if (!outcome.steps.every(step => step.status === 'passed' && step.detail)) throw new Error('C30 workflow reported an incomplete step');
  if (!isDeepStrictEqual(outcome.negative.map(item => item.name).sort(), scenario.negative_cases.map(item => item.id).sort())) throw new Error('C30 negative cases differ from the scenario');
  if (!outcome.negative.every(item => item.passed && item.expected === item.observed)) throw new Error('C30 negative case did not observe its typed outcome');
  if (!isDeepStrictEqual(outcome.result.accepted_sequences, c30Expected.accepted_sequences) ||
      !isDeepStrictEqual(outcome.result.acknowledged_sequences, c30Expected.acknowledged_sequences) ||
      outcome.result.dropped_sequence !== c30Expected.dropped_sequence || outcome.result.loss.count !== c30Expected.loss.count ||
      !isDeepStrictEqual(outcome.result.loss.gaps, c30Expected.loss.gaps) ||
      outcome.result.counts.config !== c30Expected.counts.config || outcome.result.counts.event !== c30Expected.counts.event ||
      outcome.result.counts.ack !== c30Expected.counts.ack || outcome.result.counts.gap !== c30Expected.counts.gap ||
      outcome.result.segments.length !== c30Expected.segments.count ||
      outcome.result.segments.reduce((total, segment) => total + segment.records, 0) !== c30Expected.segments.records ||
      !outcome.result.segments[0].sealed || outcome.result.segments[1].sealed ||
      outcome.result.triage_entries !== c30Expected.triage_entries ||
      outcome.result.retention_eligible !== c30Expected.retention.eligible ||
      outcome.result.coverage_complete !== c30Expected.retention.coverage_complete ||
      outcome.result.sensor.config_status !== c30Expected.sensor.config_status ||
      outcome.result.sensor.dropped_event_count !== c30Expected.sensor.dropped_event_count ||
      outcome.result.sensor.offline !== c30Expected.sensor.offline ||
      !outcome.result.restarted || !outcome.result.restored || !outcome.result.restore_equivalent) {
    throw new Error('C30 outcome differs from its fixture or did not restart/restore');
  }
  const c30Runtime = outcome.runtime;
  const seededOptions = {
    port: 0,
    sensorStatus: {
      directory: c30Runtime.state_dir, maxOperations: c30Runtime.storage_limits.max_operations, maxBytes: c30Runtime.storage_limits.max_bytes,
      maxManifestBytes: c30Runtime.storage_limits.max_manifest_bytes, publicKeyPath: c30Runtime.public_key_file, maxSensors: c30Runtime.config_max_sensors,
      minHeartbeatSeconds: c30Runtime.bounds.heartbeat_seconds.min, maxHeartbeatSeconds: c30Runtime.bounds.heartbeat_seconds.max,
      minSpoolLimitEvents: c30Runtime.bounds.spool_limit_events.min, maxSpoolLimitEvents: c30Runtime.bounds.spool_limit_events.max,
      minEventBatchLimit: c30Runtime.bounds.event_batch_limit.min, maxEventBatchLimit: c30Runtime.bounds.event_batch_limit.max,
    },
    incidentView: {
      stateDir: c30Runtime.state_dir, segmentsDir: c30Runtime.segments_dir, maxOperations: c30Runtime.storage_limits.max_operations,
      maxBytes: c30Runtime.storage_limits.max_bytes, maxManifestBytes: c30Runtime.storage_limits.max_manifest_bytes,
      maxSegments: c30Runtime.segment_limits.max_segments, maxRecordsPerSegment: c30Runtime.segment_limits.max_records_per_segment,
      maxBytesPerSegment: c30Runtime.segment_limits.max_bytes_per_segment, rateLimit: c30Runtime.incident.rate_limit, windowSeconds: c30Runtime.incident.window_seconds,
    },
    certificateStatus: {
      stateDir: c30Runtime.state_dir, issuerFile: c30Runtime.issuer_file, maxOperations: c30Runtime.storage_limits.max_operations,
      maxBytes: c30Runtime.storage_limits.max_bytes, maxManifestBytes: c30Runtime.storage_limits.max_manifest_bytes,
      maxSensors: c30Runtime.rotation.max_sensors, maxLifetimeSeconds: c30Runtime.rotation.max_lifetime_seconds,
      maxOverlapSeconds: c30Runtime.rotation.max_overlap_seconds, maxRecoveryTTLSeconds: c30Runtime.rotation.max_recovery_ttl_seconds,
    },
  };
  const stateManifest = await readFile(join(c30Runtime.state_dir, 'manifest.json'), 'utf8');
  const acceptedSegments = await segmentBytes(c30Runtime.segments_dir);
  for (let restart = 0; restart < 2; restart++) {
    seededServer = await startLocal(seededOptions);
    const seededBase = `http://127.0.0.1:${seededServer.server.address().port}`;
    const readyResponse = await fetch(seededBase + '/readyz');
    const readiness = await readyResponse.json();
    if (!readyResponse.ok || readiness.status !== 'ready' || readiness.engineReady !== true || readiness.storageReady !== true || readiness.providersReady !== true) {
      throw new Error('C30 seeded readiness is incomplete: ' + JSON.stringify(readiness));
    }
    const sensorSnapshot = await (await fetch(seededBase + '/api/v1/sensors')).json();
    const sensor = sensorSnapshot.sensors.find(item => item.sensor_id === c30Runtime.sensor_id);
    if (!sensor || sensor.config_status !== 'current' || sensor.dropped_event_count !== 1 || sensor.offline !== false) throw new Error('C30 sensor status differs from accepted state');
    const incidents = await (await fetch(seededBase + '/api/v1/incidents')).json();
    if (!incidents.coverage.complete || incidents.incidents.length === 0) throw new Error('C30 incident coverage is incomplete');
    const certificates = await (await fetch(seededBase + '/api/v1/certificates')).json();
    if (!certificates.sensors.some(item => item.sensor_id === c30Runtime.sensor_id && item.revision === 1 && item.status === 'current')) throw new Error('C30 certificate status differs from accepted state');
    if (await readFile(join(c30Runtime.state_dir, 'manifest.json'), 'utf8') !== stateManifest) throw new Error('C30 readiness changed the accepted manifest');
    if (!isDeepStrictEqual(await segmentBytes(c30Runtime.segments_dir), acceptedSegments)) throw new Error('C30 readiness changed accepted segment bytes');
    await seededServer.close(); seededServer = undefined;
  }
  const browserPort = await freePort();
  run(process.execPath, [join(checkout, 'node_modules', '.bin', 'playwright'), 'test', 'tests/browser/clone-to-value.spec.ts', '--reporter=line'], checkout, {
    timeout: 180000, env: { ...process.env, WEB_TEST_PORT: String(browserPort) },
  });
  const event = await readFile(join(checkout, 'tests/fixtures/miragemesh/C04/valid-event.txt'), 'utf8');
  const expected = JSON.parse(await readFile(join(checkout, 'tests/fixtures/miragemesh/C04/expected-output.json'), 'utf8'));
  const validation = JSON.parse(run(join(checkout, 'dist/engine/miragemesh'), ['--validate-event'], checkout, { input: event }));
  if (!isDeepStrictEqual(validation, expected.output)) throw new Error('Cloned engine event validation differs from its contract fixture');

  server = spawn(process.execPath, ['scripts/start-local.mjs', '--port', '0'], {
    cwd: checkout, stdio: ['ignore', 'pipe', 'pipe'],
  });
  const port = await new Promise((accept, reject) => {
    const timer = setTimeout(() => reject(new Error('Startup deadline')), 10000);
    server.once('error', error => { clearTimeout(timer); reject(error); });
    server.once('exit', () => { clearTimeout(timer); reject(new Error('Server exited')); });
    let bytes = '';
    server.stdout.on('data', data => {
      bytes += data;
      if (!bytes.includes('\n')) return;
      clearTimeout(timer);
      try { accept(JSON.parse(bytes.split('\n')[0]).port); } catch (error) { reject(error); }
    });
  });
  const base = 'http://127.0.0.1:' + port;
  const health = await fetch(base + '/readyz');
  const state = await health.json();
  if (!health.ok || state.engineReady !== true || (await fetch(base + '/api/v1/unimplemented')).status !== 503) {
    throw new Error('Incorrect readiness boundary');
  }
  if (!(await fetch(base)).ok) throw new Error('Workspace unavailable');
  const runtime = await (await fetch(base + '/api/engine/health')).json();
  if (runtime.status !== 'ok' || runtime.scope !== 'engine-runtime' || runtime.toolchain !== 'go1.27.2' || runtime.coreReady !== false) throw new Error('Incorrect engine runtime health');
  console.log(JSON.stringify({
    passed: true, stagedTree: tree,
    webOnly: {
      proof: 'real git clone -> npm run setup -> Go vet/race tests and discovery guard -> local event validation -> unified web and Go runtime startup',
      coreReady: false,
    },
    coreWorkflow: {
      scenario: 'tests/scenarios/clone-to-value.json',
      engine: 'tests/fixtures/miragemesh/C30/seed -> outcome.json',
      browser: 'tests/browser/clone-to-value.spec.ts',
      readiness: { engineReady: true, storageReady: true, providersReady: true },
      restart: true, restoreEquivalent: outcome.result.restore_equivalent,
      acceptedSequences: outcome.result.accepted_sequences, negativeCases: outcome.negative.length, passed: true,
    },
    proof: 'real git clone -> npm run setup -> full C30 reference workflow -> engine/storage/provider readiness -> restart/restore -> real browser workflow',
  }));
} finally {
  if (seededServer) await seededServer.close();
  if (server && server.exitCode === null && server.signalCode === null && server.pid) {
    server.kill('SIGTERM');
    await new Promise(accept => server.once('exit', accept));
  }
  await rm(temp, { recursive: true, force: true });
}
