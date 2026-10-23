import { test, expect } from '@playwright/test';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, rm, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { startLocal } from '../../../scripts/start-local.mjs';

const execute = promisify(execFile);

function common(directory: string) {
 return ['--rotate-certificates', '--rotation-state-dir', join(directory, 'state'), '--rotation-issuer-file', join(directory, 'issuer.pem'), '--rotation-max-operations', '128', '--rotation-max-bytes', '2097152', '--rotation-max-manifest-bytes', '131072', '--rotation-max-sensors', '16', '--rotation-max-lifetime-seconds', '86400', '--rotation-max-overlap-seconds', '3600', '--rotation-max-recovery-ttl-seconds', '900'];
}

test('real certificate state shows cutoff, offline recovery and restart at 360px without private material', async ({ page }, testInfo) => {
 const directory = await mkdtemp(join(tmpdir(), 'miragemesh-c24-browser-'));
 let running: Awaited<ReturnType<typeof startLocal>> | undefined;
 const external: string[] = [];
 page.on('request', request => { if (!request.url().startsWith('http://127.0.0.1:')) external.push(request.url()); });
 const certificateStatus = { stateDir: join(directory, 'state'), issuerFile: join(directory, 'issuer.pem'), maxOperations: 128, maxBytes: 2097152, maxManifestBytes: 131072, maxSensors: 16, maxLifetimeSeconds: 86400, maxOverlapSeconds: 3600, maxRecoveryTTLSeconds: 900 };
 try {
  await execute('go', ['run', './tests/fixtures/miragemesh/C24/seed', directory], { timeout: 30000 });
  running = await startLocal({ port: 0, certificateStatus });
  await page.setViewportSize({ width: 360, height: 800 });
  await page.goto(`http://127.0.0.1:${running.server.address().port}/#certificates`);
  await expect(page.getByRole('heading', { name: 'Certificate rotation and recovery.' })).toBeVisible({ timeout: 2000 });
  const ledger = page.getByRole('region', { name: 'Certificate status' });
  await expect(ledger).toContainText('Revision 2');
  await expect(ledger).toContainText('Old certificate rejected from');
  await expect(ledger).toContainText('Recovery is available');
  await ledger.locator('summary').focus(); await page.keyboard.press('Enter');
  await expect(ledger.locator('details')).toHaveAttribute('open', '');
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({ path: testInfo.outputPath('certificates-mobile.png'), fullPage: true });
  const response = await page.request.get(`http://127.0.0.1:${running.server.address().port}/api/v1/certificates`);
  const raw = await response.text(); expect(raw).not.toContain('PRIVATE KEY'); expect(raw).not.toContain('CERTIFICATE REQUEST'); expect(raw).not.toContain('certificate_pem');
  await running.close(); running = undefined;
  const token = join(directory, 'token');
  await execute('dist/engine/miragemesh', [...common(directory), '--rotation-action', 'issue-token', '--rotation-sensor', 'sensor-24', '--rotation-token-file', token, '--rotation-token-ttl-seconds', '600']);
  await execute('dist/engine/miragemesh', [...common(directory), '--rotation-action', 'recover', '--rotation-sensor', 'sensor-24', '--rotation-expected-revision', '2', '--rotation-csr-file', join(directory, 'recovery-csr.pem'), '--rotation-key-file', join(directory, 'issuer-key.pem'), '--rotation-token-file', token, '--rotation-lifetime-seconds', '86400', '--rotation-idempotency-key', 'c24-browser-recovery-key']);
  for (let restart = 0; restart < 2; restart++) {
   running = await startLocal({ port: 0, certificateStatus });
   await page.goto(`http://127.0.0.1:${running.server.address().port}/#certificates`);
   await expect(page.getByRole('region', { name: 'Certificate status' })).toContainText('Revision 3');
   expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
   await running.close(); running = undefined;
  }
  expect(await page.locator('body').textContent()).not.toContain((await readFile(token, 'utf8')).trim());
  expect(external).toEqual([]);
 } finally { if (running) await running.close(); await rm(directory, { recursive: true, force: true }); }
});

test('certificate status retains a stale snapshot during a failed read and rejects inconsistent coverage', async ({ page }) => {
 let interrupted = false;
 const value = { schema_version: '1', issuer_fingerprint: 'a'.repeat(64), observed_at: '2026-01-01T00:00:00Z', sensors: [{ sensor_id: '<img src=x onerror=globalThis.c24Sentinel=1>', revision: 1, fingerprint: 'b'.repeat(64), not_after: '2026-01-02T00:00:00Z', status: 'current', recovery_available: false }] };
 await page.route('**/api/v1/certificates', route => interrupted ? route.abort('failed') : route.fulfill({ json: value }));
 await page.setViewportSize({ width: 360, height: 800 }); await page.goto('/#certificates');
 await expect(page.getByRole('region', { name: 'Certificate status' })).toContainText(value.sensors[0].sensor_id);
 await expect(page.locator('main img, main script')).toHaveCount(0);
 expect(await page.evaluate(() => (globalThis as Record<string, unknown>).c24Sentinel)).toBeUndefined();
 interrupted = true; await page.getByRole('button', { name: 'Refresh certificates' }).click();
 await expect(page.getByRole('alert')).toContainText('stale');
 await expect(page.getByRole('region', { name: 'Certificate status' })).toContainText('Revision 1');
 interrupted = false; value.sensors[0].status = 'overlap';
 await page.getByRole('button', { name: 'Refresh certificates' }).click();
 await expect(page.getByRole('alert')).toContainText('invalid');
 await expect(page.getByRole('region', { name: 'Certificate status' })).toContainText('Revision 1');
 expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});

test('certificate page explains a disabled ledger without suggesting a successful rotation', async ({ page }) => {
 await page.goto('/#certificates');
 await expect(page.getByRole('alert')).toContainText('unavailable');
 await expect(page.getByRole('region', { name: 'Certificate status' })).toHaveCount(0);
});
