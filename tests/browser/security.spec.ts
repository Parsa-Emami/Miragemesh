import { test, expect } from '@playwright/test';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { request as httpRequest } from 'node:http';
import { startLocal } from '../../scripts/start-local.mjs';

const fixture = JSON.parse(await readFile(new URL('../fixtures/miragemesh/C27/security.json', import.meta.url), 'utf8'));

type RawResult = { status: number; headers: Record<string, string | string[] | undefined>; body: string };
function raw(base: string, path: string, options: { method?: string; headers?: Record<string, string>; body?: string } = {}): Promise<RawResult> {
  const url = new URL(base);
  return new Promise((resolve, reject) => {
    const request = httpRequest({ host: url.hostname, port: Number(url.port), path, method: options.method ?? 'GET', headers: options.headers, agent: false }, response => {
      const chunks: Buffer[] = [];
      response.on('data', chunk => chunks.push(chunk));
      response.on('end', () => resolve({ status: response.statusCode ?? 0, headers: response.headers, body: Buffer.concat(chunks).toString('utf8') }));
      response.on('error', reject);
    });
    request.on('error', reject);
    request.end(options.body);
  });
}

function portOf(running: Awaited<ReturnType<typeof startLocal>>): string {
  return String((running.server.address() as { port: number }).port);
}

async function seededIncidents() {
  const directory = await mkdtemp(join(tmpdir(), 'miragemesh-c27-'));
  try { await promisify(execFile)('go', ['run', './tests/fixtures/miragemesh/C22', directory], { cwd: process.cwd(), timeout: 30000 }); }
  catch (error) { await rm(directory, { recursive: true, force: true }); throw error; }
  let running = await startLocal({
    port: 0,
    incidentView: { stateDir: join(directory, 'state'), segmentsDir: join(directory, 'segments'), maxOperations: 128, maxBytes: 2097152, maxManifestBytes: 131072, maxSegments: 16, maxRecordsPerSegment: 2, maxBytesPerSegment: 32768, rateLimit: 2, windowSeconds: 60 },
  });
  return {
    directory,
    base: () => `http://127.0.0.1:${portOf(running)}`,
    close: async () => { await running.close(); await rm(directory, { recursive: true, force: true }); },
  };
}

test('shell hardening, import abuse and disabled surfaces fail closed', async ({ page }) => {
  const running = await startLocal({ port: 0 });
  const base = `http://127.0.0.1:${portOf(running)}`;
  const external: string[] = [];
  const pageErrors: string[] = [];
  page.on('request', request => { if (!request.url().startsWith(base)) external.push(request.url()); });
  page.on('pageerror', error => pageErrors.push(error.message));
  try {
    for (const path of ['/', '/healthz', '/runtime-config.json']) {
      const response = await fetch(base + path);
      expect(response.status, path).toBe(200);
      const csp = response.headers.get('content-security-policy') ?? '';
      for (const directive of fixture.headers.content_security_policy) expect(csp, path).toContain(directive);
      for (const directive of fixture.headers.forbidden_content_security_policy) expect(csp, path).not.toContain(directive);
      expect(response.headers.get('x-content-type-options'), path).toBe(fixture.headers.x_content_type_options);
      expect(response.headers.get('x-frame-options'), path).toBe(fixture.headers.x_frame_options);
      expect(response.headers.get('referrer-policy'), path).toBe(fixture.headers.referrer_policy);
      expect(response.headers.get('cache-control'), path).toBe(fixture.headers.cache_control);
    }
    const runtime = await (await fetch(base + '/runtime-config.json')).json();
    expect(Object.keys(runtime).sort()).toEqual(fixture.headers.runtime_config_keys);

    for (const item of fixture.disabled) {
      const response = await fetch(base + item.path);
      expect(response.status, item.path).toBe(item.status);
      expect(await response.json(), item.path).toEqual({ error: item.error });
    }
    const triageDisabled = await raw(base, `/api/v1/incidents/${fixture.triage.unknown_object}/triage`, {
      method: 'POST',
      headers: { Origin: base, 'Content-Type': 'application/json', 'Idempotency-Key': fixture.triage.valid.key },
      body: JSON.stringify({ status: 'investigating', reason: 'Synthetic C27 disabled surface.' }),
    });
    expect(triageDisabled.status).toBe(503);
    expect(JSON.parse(triageDisabled.body)).toEqual({ error: 'incidents_unavailable' });
    for (const path of ['/api/v1/sensors', '/api/v1/certificates', '/api/v1/updates']) {
      const response = await fetch(base + path, { method: 'POST', body: '{}' });
      expect(response.status, path).toBe(405);
      expect(response.headers.get('allow'), path).toBe('GET');
    }

    for (const headers of fixture.origin.headers) {
      const response = await raw(base, '/healthz', { headers });
      expect(response.status, JSON.stringify(headers)).toBe(fixture.origin.status);
      expect(JSON.parse(response.body)).toEqual({ error: fixture.origin.error });
    }
    for (const path of fixture.confinement.paths) {
      const response = await raw(base, path);
      expect([400, 404], path).toContain(response.status);
      for (const sentinel of fixture.confinement.forbidden_content) expect(response.body, path).not.toContain(sentinel);
    }

    await page.goto(base + '/');
    const inlineScript = await page.evaluate(() => {
      const script = document.createElement('script');
      script.textContent = 'globalThis.c27CspSentinel = 1';
      document.head.append(script);
      return (globalThis as Record<string, unknown>).c27CspSentinel ?? null;
    });
    expect(inlineScript).toBeNull();
    const externalAttempt = await page.evaluate(async () => {
      try { await fetch('https://example.invalid/c27'); return 'allowed'; } catch { return 'blocked'; }
    });
    expect(externalAttempt).toBe('blocked');

    await page.getByLabel('Choose JSON file').setInputFiles({ name: fixture.import.filename, mimeType: 'application/json', buffer: Buffer.from(fixture.import.document) });
    const preview = page.getByRole('status');
    await expect(preview).toContainText(fixture.import.filename);
    await expect(preview.locator('img,script')).toHaveCount(0);
    expect(await page.evaluate(() => (globalThis as Record<string, unknown>).c27Sentinel)).toBeUndefined();
    await page.getByLabel('Choose JSON file').setInputFiles({ name: 'unsafe.json', mimeType: 'application/json', buffer: Buffer.from(fixture.import.forbidden_document) });
    await expect(page.getByRole('alert')).toContainText('Unsafe document key.');
    await page.getByLabel('Choose JSON file').setInputFiles({ name: 'oversize.json', mimeType: 'application/json', buffer: Buffer.alloc(fixture.import.oversize_bytes, 0x61) });
    await expect(page.getByRole('alert')).toContainText('exceeds the preview limit');

    expect(pageErrors).toEqual([]);
    expect(external).toEqual([]);
  } finally { await running.close(); }
});

type TriageCase = {
  name: string;
  origin?: string | null;
  content_type?: string;
  key?: string | null;
  body_bytes?: number;
  method?: string;
  object?: 'unknown' | 'malformed';
  body?: unknown;
  status: number;
  error: string;
};
type Snapshot = { incidents: { id: string; history: { status: string; reason: string }[] }[] };

test('triage rejects forged authorization and stored payloads remain inert', async ({ page }) => {
  const local = await seededIncidents();
  const base = local.base();
  const segmentDirectory = join(local.directory, 'segments');
  const segments = (await readdir(segmentDirectory)).filter(name => name.endsWith('.jsonl'));
  const originalSegments = await Promise.all(segments.map(name => readFile(join(segmentDirectory, name), 'utf8')));
  try {
    const api = await fetch(base + '/api/v1/incidents');
    expect(api.status).toBe(200);
    expect(api.headers.get('content-security-policy')).toContain("default-src 'none'");
    const before = await api.json() as Snapshot;
    const incident = before.incidents[0];
    const beforeCounts = JSON.stringify(before.incidents.map(item => [item.id, item.history.length]));

    for (const item of fixture.triage.cases as TriageCase[]) {
      const headers: Record<string, string> = {};
      if (item.origin !== null) headers.Origin = item.origin ?? base;
      if ((item.method ?? 'POST') !== 'GET') headers['Content-Type'] = item.content_type ?? 'application/json';
      if (item.key) headers['Idempotency-Key'] = item.key;
      const object = item.object === 'unknown' ? fixture.triage.unknown_object : item.object === 'malformed' ? fixture.triage.malformed_object : incident.id;
      const body = (item.method ?? 'POST') === 'GET' ? undefined : item.body_bytes ? 'a'.repeat(item.body_bytes) : JSON.stringify(item.body ?? { status: 'investigating', reason: 'Synthetic C27 rejected case.' });
      const response = await raw(base, `/api/v1/incidents/${object}/triage`, { method: item.method ?? 'POST', headers, body });
      expect(response.status, item.name).toBe(item.status);
      expect(JSON.parse(response.body).error, item.name).toBe(item.error);
    }

    const afterRejections = await (await fetch(base + '/api/v1/incidents')).json() as Snapshot;
    expect(JSON.stringify(afterRejections.incidents.map(item => [item.id, item.history.length]))).toBe(beforeCounts);
    expect(await Promise.all(segments.map(name => readFile(join(segmentDirectory, name), 'utf8')))).toEqual(originalSegments);

    const accepted = await raw(base, `/api/v1/incidents/${incident.id}/triage`, {
      method: 'POST',
      headers: { Origin: base, 'Content-Type': 'application/json', 'Idempotency-Key': fixture.triage.valid.key },
      body: JSON.stringify({ status: fixture.triage.valid.status, reason: fixture.triage.valid.reason }),
    });
    expect(accepted.status).toBe(202);
    expect(JSON.parse(accepted.body).data.replayed).toBe(false);
    const afterWrite = await (await fetch(base + '/api/v1/incidents')).json() as Snapshot;
    const stored = afterWrite.incidents.find(item => item.id === incident.id);
    expect(stored?.history.length).toBe(incident.history.length + 1);
    expect(stored?.history.at(-1)?.reason).toBe(fixture.triage.valid.reason);

    const external: string[] = [];
    const pageErrors: string[] = [];
    page.on('request', request => { if (!request.url().startsWith(base)) external.push(request.url()); });
    page.on('pageerror', error => pageErrors.push(error.message));
    await page.setViewportSize({ width: 360, height: 800 });
    await page.goto(base + '/#incidents');
    await expect(page.getByRole('region', { name: 'Incident table', exact: true }).getByRole('row')).toHaveCount(5);
    await page.getByRole('button', { name: 'Open incident 1', exact: true }).click();
    const history = page.getByRole('region', { name: 'Triage history' });
    await expect(history).toContainText(fixture.triage.valid.reason);
    await expect(history.locator('svg,script')).toHaveCount(0);
    expect(await page.evaluate(() => (globalThis as Record<string, unknown>).c27Sentinel)).toBeUndefined();
    expect(pageErrors).toEqual([]);
    expect(external).toEqual([]);

    const replay = await raw(base, `/api/v1/incidents/${incident.id}/triage`, {
      method: 'POST',
      headers: { Origin: base, 'Content-Type': 'application/json', 'Idempotency-Key': fixture.triage.valid.key },
      body: JSON.stringify({ status: fixture.triage.valid.status, reason: fixture.triage.valid.reason }),
    });
    expect(replay.status).toBe(202);
    expect(JSON.parse(replay.body).data.replayed).toBe(true);
    const final = await (await fetch(base + '/api/v1/incidents')).json() as Snapshot;
    expect(final.incidents.find(item => item.id === incident.id)?.history.length).toBe(incident.history.length + 1);
  } finally { await local.close(); }
});
