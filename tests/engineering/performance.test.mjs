import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { percentile, selectConstraint, summarizeLatency, validateObservation, validateWorkload } from '../../scripts/benchmark-local.mjs';

const read = async path => JSON.parse(await readFile(new URL('../../' + path, import.meta.url), 'utf8'));
const scenario = await read('tests/scenarios/target-workload.json');
const positive = await read('tests/fixtures/miragemesh/C28/positive.json');
const negative = await read('tests/fixtures/miragemesh/C28/negative.json');
const expected = await read('tests/fixtures/miragemesh/C28/expected-output.json');
const fixtures = { positive, negative, expected };

test('accepts the declared C28 workload and fixture identities', () => {
  assert.deepEqual(validateWorkload(scenario, fixtures), []);
});

test('rejects malformed C28 workload metadata and inconsistent counts', () => {
  const mutations = [
    copy => { copy.scenario.schema_version = 2; },
    copy => { copy.scenario.license = ''; },
    copy => { copy.scenario.target.sensors = 0; },
    copy => { copy.scenario.target.steady_phase.events_per_second = 19; },
    copy => { copy.scenario.target.backlog_phase.events = 501; },
    copy => { copy.scenario.target.storage_limits.max_bytes = 0; },
    copy => { copy.scenario.target.segment_limits.max_records_per_segment = 0; },
    copy => { copy.scenario.target.http.endpoints = ['/../etc/passwd']; },
    copy => { copy.scenario.over_limit.batch_probe.batch_size = 64; },
    copy => { copy.scenario.fixtures = [copy.scenario.fixtures[0]]; },
    copy => { copy.fixtures.positive.samples = copy.fixtures.positive.samples.slice(0, 1); },
    copy => { copy.fixtures.negative.cases = copy.fixtures.negative.cases.slice(0, 1); },
    copy => { copy.fixtures.expected.target.total_events = 999; },
    copy => { copy.fixtures.expected.cancellation.retry_events = 49; },
  ];
  for (const mutate of mutations) {
    const copy = structuredClone({ scenario, fixtures });
    mutate(copy);
    assert.ok(validateWorkload(copy.scenario, copy.fixtures).length > 0, mutate.toString());
  }
});

test('percentiles and latency summaries use nearest-rank values', () => {
  const values = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
  assert.equal(percentile(values, 0.5), 5);
  assert.equal(percentile(values, 0.95), 10);
  assert.equal(percentile(values, 0.99), 10);
  assert.equal(percentile([], 0.5), 0);
  const summary = summarizeLatency(values);
  assert.equal(summary.count, 10);
  assert.equal(summary.min_ms, 1);
  assert.equal(summary.max_ms, 10);
  assert.equal(summary.p50_ms, 5);
});

test('requires a fully enforced 2 vCPU / 2048 MiB scope for the evidence run', () => {
  assert.match(selectConstraint({ requested: 'auto', requireConstraints: true, systemd: false, taskset: true }).error, /systemd/);
  assert.match(selectConstraint({ requested: 'systemd', systemd: false }).error, /unavailable/);
  assert.match(selectConstraint({ requested: 'none', requireConstraints: true }).error, /systemd/);
  const systemd = selectConstraint({ requested: 'auto', requireConstraints: true, systemd: true, taskset: true });
  assert.equal(systemd.mode, 'systemd');
  assert.equal(systemd.enforced.vcpu, 2);
  assert.equal(systemd.enforced.memory_mib, 2048);
  const taskset = selectConstraint({ requested: 'auto', taskset: true });
  assert.equal(taskset.mode, 'taskset');
  assert.equal(taskset.enforced.memory_mib, null);
});

function validObservation() {
  return {
    schema_version: 1,
    task: 'C28',
    source_identity: 'sha256:' + 'a'.repeat(64),
    environment: { os: 'linux', go: 'go1.27.2', engine_sha256: 'b'.repeat(64) },
    constraints: { mode: 'systemd' },
    fixtures: [{ sha256: 'c'.repeat(64) }, { sha256: 'd'.repeat(64) }, { sha256: 'e'.repeat(64) }],
    assertions: [{ name: 'target_events', passed: true }],
    limits_published: { sustained_events_per_second: 8 },
    target: { ingest: { steady: { events_per_second: 8 }, events: 740, acks: 740 } },
    over_limit: { rate_probe: { planned_events: 200, completed_events: 130, events_per_second: 13 } },
  };
}

test('accepts a complete measured observation and rejects unproved claims', () => {
  assert.deepEqual(validateObservation(validObservation(), scenario, expected), []);
  const mutations = [
    observation => { observation.source_identity = 'unknown'; },
    observation => { observation.assertions[0].passed = false; },
    observation => { observation.limits_published.sustained_events_per_second = 9; },
    observation => { observation.target.ingest.events = 999; },
    observation => { observation.over_limit.rate_probe.completed_events = 200; },
    observation => { observation.fixtures = observation.fixtures.slice(0, 2); },
    observation => { observation.environment.engine_sha256 = ''; },
    observation => { delete observation.limits_published; },
  ];
  for (const mutate of mutations) {
    const observation = validObservation();
    mutate(observation);
    assert.ok(validateObservation(observation, scenario, expected).length > 0, mutate.toString());
  }
});
