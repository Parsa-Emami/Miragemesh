import { test, expect } from '@playwright/test';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { startLocal } from '../../../scripts/start-local.mjs';

async function localIncidents() {
  const directory = await mkdtemp(join(tmpdir(), 'miragemesh-c22-browser-'));
  try { await promisify(execFile)('go', ['run', './tests/fixtures/miragemesh/C22', directory], { cwd: process.cwd(), timeout: 30000 }); }
  catch (error) { await rm(directory, { recursive: true, force: true }); throw error; }
  const options = { port: 0, incidentView: { stateDir: join(directory, 'state'), segmentsDir: join(directory, 'segments'), maxOperations: 128, maxBytes: 2097152, maxManifestBytes: 131072, maxSegments: 16, maxRecordsPerSegment: 2, maxBytesPerSegment: 32768, rateLimit: 2, windowSeconds: 60 } };
  let running = await startLocal(options);
  return {
    directory,
    base: () => `http://127.0.0.1:${running.server.address().port}`,
    restart: async () => { await running.close(); running = await startLocal(options); },
    close: async () => { await running.close(); await rm(directory, { recursive: true, force: true }); },
  };
}

test('real incident replay escapes source bytes and keyboard triage survives engine restart', async ({ page }, testInfo) => {
  const local = await localIncidents();
  const external: string[] = [];
  page.on('request', request => { if (!request.url().startsWith('http://127.0.0.1:')) external.push(request.url()); });
  const segmentDirectory = join(local.directory, 'segments');
  const segments = (await readdir(segmentDirectory)).filter(name => name.endsWith('.jsonl'));
  const original = await Promise.all(segments.map(name => readFile(join(segmentDirectory, name), 'utf8')));
  try {
    await page.setViewportSize({ width: 360, height: 800 });
    await page.goto(local.base() + '/#incidents');
    const list = page.getByRole('region', { name: 'Incident table', exact: true });
    await expect(list.getByRole('row')).toHaveCount(5);
    await list.getByRole('button', { name: 'Open incident 1', exact: true }).focus();
    await page.keyboard.press('Enter');
    await expect(page.getByRole('region', { name: 'Selected incident' })).toBeFocused();
    await expect(page.getByTestId('event-path')).toHaveText('/<img src=x onerror=globalThis.c22Sentinel=1>');
    await expect(page.locator('.source-trace')).toContainText('segment-00000000000000000001');
    await expect(page.getByRole('region', { name: 'Selected incident' }).locator('img,script')).toHaveCount(0);
    expect(await page.evaluate(() => (globalThis as Record<string, unknown>).c22Sentinel)).toBeUndefined();
    await page.screenshot({ path: testInfo.outputPath('incidents-mobile.png'), fullPage: true });
    await page.getByRole('button', { name: 'Next event', exact: true }).focus();
    await page.keyboard.press('Enter');
    await expect(page.getByTestId('event-path')).toHaveText('/second');
    await page.getByRole('button', { name: 'Replay event 3', exact: true }).focus();
    await page.keyboard.press('Enter');
    await expect(page.getByTestId('event-path')).toHaveText('/third');
    const reason = 'Synthetic review <script>globalThis.c22Sentinel=2</script>';
    await page.getByLabel('Triage reason').fill(reason);
    await page.getByRole('button', { name: 'Save triage', exact: true }).focus();
    await page.keyboard.press('Enter');
    await expect(page.getByRole('region', { name: 'Triage history' })).toContainText(reason);
    await local.restart();
    await page.goto(local.base() + '/#incidents');
    await expect(page.getByRole('region', { name: 'Triage history' }).getByRole('listitem')).toHaveCount(1);
    await expect(page.getByRole('region', { name: 'Triage history' })).toContainText(reason);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    expect(await page.evaluate(() => (globalThis as Record<string, unknown>).c22Sentinel)).toBeUndefined();
    expect(await Promise.all(segments.map(name => readFile(join(segmentDirectory, name), 'utf8')))).toEqual(original);
    expect(external).toEqual([]);
  } finally { await local.close(); }
});

test('a committed but interrupted triage retries the same key without duplicating history', async ({ page }) => {
  const local = await localIncidents();
  const keys: string[] = [];
  let lost = false;
  try {
    await page.route('**/api/v1/incidents/*/triage', async route => {
      keys.push(route.request().headers()['idempotency-key']);
      const response = await route.fetch();
      expect(response.status()).toBe(202);
      if (!lost) { lost = true; await route.abort('failed'); }
      else { expect((await response.json()).data.replayed).toBe(true); await route.fulfill({ response }); }
    });
    await page.goto(local.base() + '/#incidents');
    await page.getByLabel('Triage reason').fill('Lost response recovery, synthetic.');
    await page.getByRole('button', { name: 'Save triage', exact: true }).click();
    await expect(page.getByRole('alert')).toContainText('unknown');
    await expect(page.getByLabel('Triage reason')).toBeDisabled();
    await page.getByRole('button', { name: 'Retry same triage', exact: true }).click();
    await expect(page.getByRole('region', { name: 'Triage history' }).getByRole('listitem')).toHaveCount(1);
    expect(keys).toHaveLength(2);
    expect(keys[0]).toBe(keys[1]);
  } finally { await local.close(); }
});

test('empty coverage and interrupted reads are explicit and retain a stale snapshot at 360px', async ({ page }) => {
  let interrupted = false;
  await page.route('**/api/v1/incidents', route => interrupted ? route.abort('failed') : route.fulfill({ json: { schema_version: '1', coverage: { complete: false, missing_ordinals: [{ after: 1, before: 3 }], incomplete_segments: 1 }, unprojected_events: 1, rate_limit: 2, window_seconds: 60, incidents: [] } }));
  await page.setViewportSize({ width: 360, height: 800 });
  await page.goto('/#incidents');
  await expect(page.getByText('No incidents in the projected segments.')).toBeVisible();
  await expect(page.getByRole('region', { name: 'Evidence coverage' })).toContainText('incomplete');
  interrupted = true;
  await page.getByRole('button', { name: 'Refresh incidents' }).click();
  await expect(page.getByRole('alert')).toContainText('stale');
  await expect(page.getByText('No incidents in the projected segments.')).toBeVisible();
  interrupted = false;
  await page.getByRole('button', { name: 'Refresh incidents' }).click();
  await expect(page.getByRole('alert')).toHaveCount(0);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});

test('incidents explains the disabled engine at 360px without egress', async ({ page }) => {
  const external: string[] = [];
  page.on('request', request => { if (!request.url().startsWith('http://127.0.0.1:')) external.push(request.url()); });
  await page.setViewportSize({ width: 360, height: 800 });
  await page.goto('/#incidents');
  await expect(page.getByRole('heading', { name: 'Incident replay and triage.' })).toBeVisible();
  await expect(page.getByRole('alert')).toContainText('unavailable');
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  expect(external).toEqual([]);
});

test('incidents rejects an invalid response without presenting it as empty', async ({ page }) => {
  await page.route('**/api/v1/incidents', route => route.fulfill({ json: { schema_version: '2', incidents: [] } }));
  await page.goto('/#incidents');
  await expect(page.getByRole('alert')).toContainText('invalid');
  await expect(page.getByText('No incidents in the projected segments.')).toHaveCount(0);
});
