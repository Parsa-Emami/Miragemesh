import { test, expect } from '@playwright/test';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { startLocal } from '../../../scripts/start-local.mjs';

test('real retention audit is keyboard accessible, inert and durable at 360px', async ({ page }) => {
  const directory = await mkdtemp(join(tmpdir(), 'miragemesh-c23-browser-'));
  let running: Awaited<ReturnType<typeof startLocal>> | undefined;
  const run = promisify(execFile);
  const external: string[] = [];
  page.on('request', request => { if (!request.url().startsWith('http://127.0.0.1:')) external.push(request.url()); });
  try {
    await run('go', ['run', './tests/fixtures/miragemesh/C23', directory], { timeout: 30000 });
    const manifest = await readFile(join(directory, 'state', 'manifest.json'), 'utf8');
    const reason = 'Synthetic retention <img src=x onerror=globalThis.c23Sentinel=1>';
    const applied = await run('dist/engine/miragemesh', ['--expire-segments', '--retention-apply', '--retention-dir', join(directory, 'segments'), '--retention-before', '2026-01-05T00:00:00Z', '--retention-reason', reason, '--retention-key', 'c23-browser-synthetic-key', '--retention-max-segments', '16', '--retention-max-records', '2', '--retention-max-bytes', '32768']);
    expect(JSON.parse(applied.stdout).result.segments).toHaveLength(2);
    const projected = await run('dist/engine/miragemesh', ['--project-segments', '--storage-dir', join(directory, 'state'), '--segments-dir', join(directory, 'segments'), '--storage-max-operations', '128', '--storage-max-bytes', '2097152', '--storage-max-manifest-bytes', '131072', '--segments-max-count', '16', '--segments-max-records', '2', '--segments-max-bytes', '32768']);
    expect(JSON.parse(projected.stdout).retained).toBe(4);
    expect(JSON.parse(projected.stdout).appended).toBe(0);
    await page.setViewportSize({ width: 360, height: 800 });
    for (let restart = 0; restart < 2; restart++) {
      running = await startLocal({ port: 0, incidentView: { stateDir: join(directory, 'state'), segmentsDir: join(directory, 'segments'), maxOperations: 128, maxBytes: 2097152, maxManifestBytes: 131072, maxSegments: 16, maxRecordsPerSegment: 2, maxBytesPerSegment: 32768, rateLimit: 10, windowSeconds: 60 } });
      await page.goto(`http://127.0.0.1:${running.server.address().port}/#incidents`);
      const coverage = page.getByRole('region', { name: 'Evidence coverage' });
      await expect(coverage).toContainText('4 deliberately expired event sources');
      await expect(coverage).toContainText('0 unprojected events');
      await expect(coverage).toContainText('coverage is incomplete');
      const summary = coverage.locator('summary');
      await expect(summary).toHaveText('Retention audit (2 segments)');
      await summary.focus(); await page.keyboard.press('Enter');
      await expect(coverage.locator('details')).toHaveAttribute('open', '');
      await expect(coverage.locator('details')).toContainText(reason);
      await expect(coverage.locator('details img, details script')).toHaveCount(0);
      expect(await page.evaluate(() => (globalThis as Record<string, unknown>).c23Sentinel)).toBeUndefined();
      await expect(page.getByRole('region', { name: 'Incident table', exact: true }).getByRole('row')).toHaveCount(3);
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
      await running.close(); running = undefined;
    }
    expect(await readFile(join(directory, 'state', 'manifest.json'), 'utf8')).toBe(manifest);
    expect(external).toEqual([]);
  } finally { if (running) await running.close(); await rm(directory, { recursive: true, force: true }); }
});
