import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, readdir, writeFile, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { startLocal } from './start-local.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const output = resolve(process.argv[2] ?? join(tmpdir(), 'miragemesh-installed-proof.json'));
const work = await mkdtemp(join(tmpdir(), 'miragemesh-installed-'));
const run = (file, args, options = {}) => {
  const result = spawnSync(file, args, { cwd: root, encoding: 'utf8', timeout: 120000, maxBuffer: 4 * 1024 * 1024, ...options });
  assert.equal(result.status, 0, result.stderr || result.stdout || result.error?.message);
  return JSON.parse(result.stdout);
};
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const segmentHashes = async directory => Object.fromEntries(await Promise.all((await readdir(directory)).filter(name => name.endsWith('.jsonl')).sort().map(async name => [name, hash(await readFile(join(directory, name)))])));
const scenario = JSON.parse(await readFile(join(root, 'tests/scenarios/clone-to-value.json'), 'utf8'));
const version = JSON.parse(await readFile(join(root, 'package.json'), 'utf8')).version;
const engine = join(root, 'dist/engine/miragemesh');
const versionResult = spawnSync(engine, ['--version'], { encoding: 'utf8', timeout: 5000 });
assert.equal(versionResult.status, 0, versionResult.stderr);
assert.ok(versionResult.stdout.includes(version));
const outcome = run(join(root, 'dist/verification/reference-workflow'), [join(work, 'reference')]);
assert.deepEqual(outcome.steps.map(step => step.name), scenario.steps.map(step => step.id));
assert.ok(outcome.steps.every(step => step.status === 'passed' && step.detail));
assert.equal(outcome.negative.length, scenario.negative_cases.length);
assert.ok(outcome.negative.every(result => result.passed && result.expected === result.observed));
assert.equal(outcome.result.restarted, true);
assert.equal(outcome.result.restored, true);
assert.equal(outcome.result.restore_equivalent, true);
const r = outcome.runtime;
const options = {
  port: 0,
  sensorStatus: {
    directory: r.state_dir, maxOperations: r.storage_limits.max_operations, maxBytes: r.storage_limits.max_bytes, maxManifestBytes: r.storage_limits.max_manifest_bytes,
    publicKeyPath: r.public_key_file, maxSensors: r.config_max_sensors,
    minHeartbeatSeconds: r.bounds.heartbeat_seconds.min, maxHeartbeatSeconds: r.bounds.heartbeat_seconds.max,
    minSpoolLimitEvents: r.bounds.spool_limit_events.min, maxSpoolLimitEvents: r.bounds.spool_limit_events.max,
    minEventBatchLimit: r.bounds.event_batch_limit.min, maxEventBatchLimit: r.bounds.event_batch_limit.max,
  },
  incidentView: {
    stateDir: r.state_dir, segmentsDir: r.segments_dir, maxOperations: r.storage_limits.max_operations, maxBytes: r.storage_limits.max_bytes,
    maxManifestBytes: r.storage_limits.max_manifest_bytes, maxSegments: r.segment_limits.max_segments, maxRecordsPerSegment: r.segment_limits.max_records_per_segment,
    maxBytesPerSegment: r.segment_limits.max_bytes_per_segment, rateLimit: r.incident.rate_limit, windowSeconds: r.incident.window_seconds,
  },
  certificateStatus: {
    stateDir: r.state_dir, issuerFile: r.issuer_file, maxOperations: r.storage_limits.max_operations, maxBytes: r.storage_limits.max_bytes,
    maxManifestBytes: r.storage_limits.max_manifest_bytes, maxSensors: r.rotation.max_sensors, maxLifetimeSeconds: r.rotation.max_lifetime_seconds,
    maxOverlapSeconds: r.rotation.max_overlap_seconds, maxRecoveryTTLSeconds: r.rotation.max_recovery_ttl_seconds,
  },
};
const before = hash(await readFile(join(r.state_dir, 'manifest.json')));
const segments = await segmentHashes(r.segments_dir);
for (let cycle = 0; cycle < 2; cycle++) {
  const running = await startLocal(options);
  try {
    const base = `http://127.0.0.1:${running.server.address().port}`;
    const ready = await fetch(base + '/readyz');
    assert.equal(ready.status, 200);
    assert.equal((await ready.json()).engineReady, true);
    const sensors = await (await fetch(base + '/api/v1/sensors')).json();
    assert.ok(sensors.sensors.some(sensor => sensor.sensor_id === r.sensor_id && sensor.dropped_event_count === 1));
    const incidents = await (await fetch(base + '/api/v1/incidents')).json();
    assert.equal(incidents.coverage.complete, true);
    assert.ok(incidents.incidents.length > 0);
    const certificates = await (await fetch(base + '/api/v1/certificates')).json();
    assert.ok(certificates.sensors.some(sensor => sensor.sensor_id === r.sensor_id && sensor.status === 'current'));
    const health = await (await fetch(base + '/api/engine/health')).json();
    assert.equal(health.version, version);
  } finally { await running.close(); }
}
assert.equal(hash(await readFile(join(r.state_dir, 'manifest.json'))), before);
assert.deepEqual(await segmentHashes(r.segments_dir), segments);
await mkdir(join(output, '..'), { recursive: true });
await writeFile(output, JSON.stringify({ schema_version: 1, project: 'MirageMesh', commit_id: 'C40', passed: true, kind: 'installed-published-artifact', version, platform: 'linux-amd64', installed_root: root, engine_sha256: hash(await readFile(engine)), verification_binary_sha256: hash(await readFile(join(root, 'dist/verification/reference-workflow'))), steps: outcome.steps, negative: outcome.negative, restart: true, restore_equivalent: true, installed_engine_restart_cycles: 2, accepted_state_unchanged: true, state_manifest_sha256: before, segment_sha256: segments }, null, 2) + '\n');
console.log(JSON.stringify({ passed: true, output, steps: outcome.steps.length, negative_cases: outcome.negative.length, restart_restore: true }));
