import { test, expect } from '@playwright/test';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { startLocal } from '../../scripts/start-local.mjs';

const execute = promisify(execFile);
const repository = process.cwd();
const scenario = JSON.parse(await readFile(new URL('../scenarios/clone-to-value.json', import.meta.url), 'utf8'));

type Outcome = {
  steps: { name: string; status: string; detail: string }[];
  negative: { name: string; expected: string; observed: string; passed: boolean }[];
  result: {
    sensor: { config_status: string; dropped_event_count: number; offline: boolean };
    triage_entries: number;
    accepted_sequences: number[];
  };
  runtime: {
    state_dir: string; segments_dir: string; sensor_id: string;
    public_key_file: string; issuer_file: string;
    storage_limits: { max_operations: number; max_bytes: number; max_manifest_bytes: number };
    segment_limits: { max_segments: number; max_records_per_segment: number; max_bytes_per_segment: number };
    config_max_sensors: number;
    bounds: {
      heartbeat_seconds: { min: number; max: number };
      spool_limit_events: { min: number; max: number };
      event_batch_limit: { min: number; max: number };
    };
    incident: { rate_limit: number; window_seconds: number };
    rotation: { max_sensors: number; max_lifetime_seconds: number; max_overlap_seconds: number; max_recovery_ttl_seconds: number };
  };
};

async function seed(directory: string): Promise<Outcome> {
  await execute('go', ['run', './tests/fixtures/miragemesh/C30/seed', directory], {
    cwd: repository, timeout: 60000,
    env: { ...process.env, GOTOOLCHAIN: 'go1.27.2', GOSUMDB: 'sum.golang.org', GOPROXY: 'https://proxy.golang.org|direct' },
  });
  return JSON.parse(await readFile(join(directory, 'outcome.json'), 'utf8')) as Outcome;
}

function launchOptions(outcome: Outcome) {
  const runtime = outcome.runtime;
  return {
    port: 0,
    sensorStatus: {
      directory: runtime.state_dir,
      maxOperations: runtime.storage_limits.max_operations,
      maxBytes: runtime.storage_limits.max_bytes,
      maxManifestBytes: runtime.storage_limits.max_manifest_bytes,
      publicKeyPath: runtime.public_key_file,
      maxSensors: runtime.config_max_sensors,
      minHeartbeatSeconds: runtime.bounds.heartbeat_seconds.min,
      maxHeartbeatSeconds: runtime.bounds.heartbeat_seconds.max,
      minSpoolLimitEvents: runtime.bounds.spool_limit_events.min,
      maxSpoolLimitEvents: runtime.bounds.spool_limit_events.max,
      minEventBatchLimit: runtime.bounds.event_batch_limit.min,
      maxEventBatchLimit: runtime.bounds.event_batch_limit.max,
    },
    incidentView: {
      stateDir: runtime.state_dir,
      segmentsDir: runtime.segments_dir,
      maxOperations: runtime.storage_limits.max_operations,
      maxBytes: runtime.storage_limits.max_bytes,
      maxManifestBytes: runtime.storage_limits.max_manifest_bytes,
      maxSegments: runtime.segment_limits.max_segments,
      maxRecordsPerSegment: runtime.segment_limits.max_records_per_segment,
      maxBytesPerSegment: runtime.segment_limits.max_bytes_per_segment,
      rateLimit: runtime.incident.rate_limit,
      windowSeconds: runtime.incident.window_seconds,
    },
    certificateStatus: {
      stateDir: runtime.state_dir,
      issuerFile: runtime.issuer_file,
      maxOperations: runtime.storage_limits.max_operations,
      maxBytes: runtime.storage_limits.max_bytes,
      maxManifestBytes: runtime.storage_limits.max_manifest_bytes,
      maxSensors: runtime.rotation.max_sensors,
      maxLifetimeSeconds: runtime.rotation.max_lifetime_seconds,
      maxOverlapSeconds: runtime.rotation.max_overlap_seconds,
      maxRecoveryTTLSeconds: runtime.rotation.max_recovery_ttl_seconds,
    },
  };
}

async function segments(directory: string): Promise<Record<string, string>> {
  const entries = (await readdir(directory)).filter(name => name.endsWith('.jsonl')).sort();
  const output: Record<string, string> = {};
  for (const name of entries) output[name] = await readFile(join(directory, name), 'utf8');
  return output;
}

test('clone-to-value: real seeded engine state completes the reference workflow and survives restart', async ({ page }, testInfo) => {
  const directory = await mkdtemp(join(tmpdir(), 'miragemesh-c30-browser-'));
  let running: Awaited<ReturnType<typeof startLocal>> | undefined;
  const external: string[] = [];
  page.on('request', request => { if (!request.url().startsWith('http://127.0.0.1:')) external.push(request.url()); });
  try {
    const outcome = await seed(directory);
    expect(outcome.steps.map(step => step.name)).toEqual(scenario.steps.map((step: { id: string }) => step.id));
    expect(outcome.steps.every(step => step.status === 'passed' && step.detail.length > 0)).toBe(true);
    expect(outcome.negative.map(item => item.name).sort()).toEqual(scenario.negative_cases.map((item: { id: string }) => item.id).sort());
    expect(outcome.negative.every(item => item.passed && item.expected === item.observed)).toBe(true);
    expect(outcome.result.sensor.config_status).toBe('current');
    expect(outcome.result.sensor.dropped_event_count).toBe(1);
    expect(outcome.result.sensor.offline).toBe(false);
    expect(outcome.result.accepted_sequences).toEqual([1, 2, 3, 5]);

    const options = launchOptions(outcome);
    const stateManifest = await readFile(join(directory, 'state', 'manifest.json'), 'utf8');
    const segmentBytes = await segments(join(directory, 'segments'));

    for (let restart = 0; restart < 2; restart++) {
      running = await startLocal(options);
      const base = `http://127.0.0.1:${(running.server.address() as { port: number }).port}`;
      const ready = await fetch(base + '/readyz');
      const readiness = await ready.json();
      expect(ready.status, JSON.stringify(readiness)).toBe(200);
      expect(readiness).toMatchObject({ status: 'ready', engineReady: true, storageReady: true, providersReady: true });
      const sensors = await (await fetch(base + '/api/v1/sensors')).json();
      const sensor = sensors.sensors.find((item: { sensor_id: string }) => item.sensor_id === outcome.runtime.sensor_id);
      expect(sensor).toMatchObject({ config_status: 'current', dropped_event_count: 1, offline: false });
      const incidents = await (await fetch(base + '/api/v1/incidents')).json();
      expect(incidents.coverage.complete).toBe(true);
      expect(incidents.incidents.length).toBeGreaterThan(0);
      const certificates = await (await fetch(base + '/api/v1/certificates')).json();
      expect(certificates.sensors).toEqual(expect.arrayContaining([expect.objectContaining({ sensor_id: outcome.runtime.sensor_id, revision: 1, status: 'current' })]));

      await page.setViewportSize({ width: 360, height: 800 });
      await page.goto(base + '/#sensors');
      await expect(page.getByRole('heading', { name: 'Sensor health and spool pressure.' })).toBeVisible();
      const summary = page.getByRole('region', { name: 'Sensor summary' });
      await expect(summary.getByRole('row', { name: /sensor-01/ })).toContainText('Online by recent event');
      await expect(summary.getByRole('row', { name: /sensor-01/ })).toContainText('current');
      await expect(summary.locator('.sensor-metrics')).toContainText('1');
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);

      await page.goto(base + '/#incidents');
      await expect(page.getByRole('region', { name: 'Evidence coverage' })).toContainText('Available segment coverage is complete.');
      const table = page.getByRole('region', { name: 'Incident table', exact: true });
      await expect(table.getByRole('button', { name: 'Open incident 1', exact: true })).toBeVisible();
      await table.getByRole('button', { name: 'Open incident 1', exact: true }).click();
      await expect(page.getByRole('region', { name: 'Triage history' })).toContainText('Synthetic C30 review of accepted synthetic events.');
      await expect(page.getByRole('region', { name: 'Triage history' }).getByRole('listitem')).toHaveCount(1);

      await page.goto(base + '/#certificates');
      const certificatesRegion = page.getByRole('region', { name: 'Certificate status' });
      await expect(certificatesRegion).toContainText('Revision 1');
      await expect(certificatesRegion).toContainText('sensor-01');
      await expect(certificatesRegion).toContainText('Current certificate');

      const pageText = await page.locator('body').textContent();
      const apiText = [await (await fetch(base + '/api/v1/sensors')).text(), await (await fetch(base + '/api/v1/incidents')).text(), await (await fetch(base + '/api/v1/certificates')).text()].join('\n');
      for (const body of [pageText ?? '', apiText]) {
        expect(body).not.toContain('PRIVATE KEY');
        expect(body).not.toContain('CERTIFICATE REQUEST');
      }
      expect(await readFile(join(directory, 'state', 'manifest.json'), 'utf8')).toBe(stateManifest);
      expect(await segments(join(directory, 'segments'))).toEqual(segmentBytes);
      await running.close();
      running = undefined;
    }
    expect(external).toEqual([]);
    await page.screenshot({ path: testInfo.outputPath('clone-to-value.png'), fullPage: true });
  } finally {
    if (running) await running.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test('C36: unavailable local providers remain explicit and recovery reopens the accepted state', async ({ page }) => {
  const directory = await mkdtemp(join(tmpdir(), 'miragemesh-c36-browser-'));
  let running: Awaited<ReturnType<typeof startLocal>> | undefined;
  const external: string[] = [];
  page.on('request', request => { if (!request.url().startsWith('http://127.0.0.1:')) external.push(request.url()); });
  try {
    running = await startLocal({ port: 0 });
    const unavailableBase = `http://127.0.0.1:${(running.server.address() as { port: number }).port}`;
    const unavailable = await fetch(unavailableBase + '/api/v1/sensors');
    expect(unavailable.status).toBe(503);
    await page.goto(unavailableBase + '/#sensors');
    await expect(page.getByRole('alert')).toContainText('Sensor status is unavailable');
    await running.close();
    running = undefined;

    const outcome = await seed(directory);
    const options = launchOptions(outcome);
    const manifest = await readFile(join(directory, 'state/manifest.json'), 'utf8');
    const acceptedSegments = await segments(join(directory, 'segments'));
    await expect(startLocal({ ...options, certificateStatus: { ...options.certificateStatus, issuerFile: join(directory, 'missing-required-issuer.pem') } })).rejects.toThrow();
    expect(await readFile(join(directory, 'state/manifest.json'), 'utf8')).toBe(manifest);
    for (let restart = 0; restart < 2; restart++) {
      running = await startLocal(options);
      const base = `http://127.0.0.1:${(running.server.address() as { port: number }).port}`;
      const readiness = await fetch(base + '/readyz');
      expect(readiness.status).toBe(200);
      expect(await readiness.json()).toMatchObject({ engineReady: true, storageReady: true, providersReady: true });
      await page.setViewportSize({ width: 360, height: 800 });
      await page.goto(base + '/#sensors');
      const summary = page.getByRole('region', { name: 'Sensor summary' });
      await expect(summary.getByRole('row', { name: /sensor-01/ })).toContainText('current');
      await expect(page.getByRole('alert')).toHaveCount(0);
      await page.goto(base + '/#certificates');
      await expect(page.getByRole('region', { name: 'Certificate status' })).toContainText('Current certificate');
      expect(await readFile(join(directory, 'state/manifest.json'), 'utf8')).toBe(manifest);
      expect(await segments(join(directory, 'segments'))).toEqual(acceptedSegments);
      await running.close();
      running = undefined;
    }
    expect(external).toEqual([]);
  } finally {
    if (running) await running.close();
    await rm(directory, { recursive: true, force: true });
  }
});
