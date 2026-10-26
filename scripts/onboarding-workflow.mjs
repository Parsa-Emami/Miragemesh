import { spawn, spawnSync } from 'node:child_process';
import { readFile, readdir, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { createServer } from 'node:net';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isDeepStrictEqual } from 'node:util';
import { goEnvironment } from './oss-bootstrap.mjs';
import { startLocal } from './start-local.mjs';
import { loadOnboarding } from './onboarding-contract.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const checkout = root;
let server;
let seededServer;
if (process.argv.length !== 4 || resolve(process.cwd()) !== resolve(root)) throw new Error('Run the onboarding worker from its own clean checkout with fresh state and report paths');

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
    cwd, timeout: 180000, encoding: 'utf8', maxBuffer: 8 * 1024 * 1024, ...options,
  });
  if (result.status !== 0) {
    throw new Error(`${command} failed: ${result.stdout ?? ''}${result.stderr ?? result.error?.message ?? ''}`);
  }
  return result.stdout.trim();
}

try {
  const c30 = resolve(process.argv[2]);
  const { scenario: onboardingScenario, positive, negative, expected: onboardingExpected } = await loadOnboarding(root);
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
  const independentExpected = onboardingExpected.workflow;
  if (!isDeepStrictEqual(outcome.result.accepted_sequences, independentExpected.accepted_sequences) || outcome.result.dropped_sequence !== independentExpected.dropped_sequence || outcome.result.loss.count !== independentExpected.loss_count || outcome.result.applied_revision !== independentExpected.applied_revision || outcome.result.triage_entries !== independentExpected.triage_entries || outcome.result.restarted !== independentExpected.restart || outcome.result.restore_equivalent !== independentExpected.restore_equivalent) throw new Error('C36 independent expectations differ from the observed reference workflow');
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
  let providerFailure;
  try {
    const unexpected = await startLocal({ ...seededOptions, certificateStatus: { ...seededOptions.certificateStatus, issuerFile: join(c30, 'missing-required-issuer.pem') } });
    await unexpected.close();
  } catch { providerFailure = 'onboarding.provider_unavailable'; }
  if (providerFailure !== onboardingExpected.provider_failure) throw new Error('Missing required certificate provider did not fail explicitly');
  if (await readFile(join(c30Runtime.state_dir, 'manifest.json'), 'utf8') !== stateManifest || !isDeepStrictEqual(await segmentBytes(c30Runtime.segments_dir), acceptedSegments)) throw new Error('Unavailable provider changed accepted state');
  for (let restart = 0; restart < onboardingScenario.onboarding.restart_cycles; restart++) {
    seededServer = await startLocal(seededOptions);
    const seededBase = `http://127.0.0.1:${seededServer.server.address().port}`;
    const readyResponse = await fetch(seededBase + '/readyz');
    const readiness = await readyResponse.json();
    if (!readyResponse.ok || !Object.entries(onboardingExpected.readiness).every(([key, expected]) => readiness[key] === expected)) {
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
  run(process.execPath, [join(checkout, 'node_modules', '.bin', 'playwright'), 'test', ...onboardingScenario.onboarding.browser_workflows, '--reporter=line'], checkout, {
    timeout: 180000, env: { ...process.env, WEB_TEST_PORT: String(browserPort) },
  });
  const event = await readFile(join(checkout, 'tests/fixtures/miragemesh/C04/valid-event.txt'), 'utf8');
  const expected = JSON.parse(await readFile(join(checkout, 'tests/fixtures/miragemesh/C04/expected-output.json'), 'utf8'));
  const validation = JSON.parse(run(join(checkout, 'dist/engine/miragemesh'), ['--validate-event'], checkout, { input: event }));
  if (!isDeepStrictEqual(validation, expected.output)) throw new Error('Cloned engine event validation differs from its contract fixture');

  const eventChecks = [];
  for (const [name, fixture, expectedExit] of [['positive', positive, 0], ['negative', negative, 1]]) {
    const input = JSON.stringify(fixture.event);
    const check = spawnSync(join(root, 'dist/engine/miragemesh'), ['--validate-event'], { cwd: root, encoding: 'utf8', input, timeout: 5000 });
    if (check.error || check.status !== expectedExit) throw new Error('C36 event probe did not observe its declared exit');
    const result = JSON.parse(check.stdout);
    if (result.input_digest !== createHash('sha256').update(input).digest('hex')) throw new Error('C36 event digest differs from exact fixture bytes');
    if (name === 'positive' && !isDeepStrictEqual(result.result, onboardingExpected.event.result)) throw new Error('C36 valid sensor event outcome differs');
    if (name === 'negative' && (result.status !== 'failed' || result.result.error.code !== onboardingExpected.invalid_event.code)) throw new Error('C36 malformed sensor event was not rejected explicitly');
    eventChecks.push({ name, exit_code: check.status, result: result.result });
  }
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
  const report = {
    passed: true, implementation_root: root,
    provider_failure: providerFailure,
    event_checks: eventChecks,
    state_manifest_sha256: createHash('sha256').update(stateManifest).digest('hex'),
    segment_sha256: Object.fromEntries(Object.entries(acceptedSegments).map(([name, bytes]) => [name, createHash('sha256').update(bytes).digest('hex')])),
    engine_sha256: createHash('sha256').update(await readFile(join(root, 'dist/engine/miragemesh'))).digest('hex'),
    web_index_sha256: createHash('sha256').update(await readFile(join(root, 'dist/web/index.html'))).digest('hex'),
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
  };
  await writeFile(resolve(process.argv[3]), JSON.stringify(report, null, 2) + '\n');
  console.log(JSON.stringify(report));

} finally {
  if (seededServer) await seededServer.close();
  if (server && server.exitCode === null && server.signalCode === null && server.pid) {
    server.kill('SIGTERM');
    await new Promise(accept => server.once('exit', accept));
  }
}
