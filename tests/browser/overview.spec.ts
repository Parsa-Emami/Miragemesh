import { test, expect } from '@playwright/test';
import { readFileSync } from 'node:fs';
const fixture = JSON.parse(readFileSync(new URL('../fixtures/miragemesh/C21/expected-output.json', import.meta.url), 'utf8'));
const snapshot = { schema_version: fixture.schema_version, offline_after_seconds: fixture.offline_after_seconds, sensors: fixture.sensors };

test('overview uses validated local snapshots and leaves unavailable incident coverage unknown', async ({ page }) => {
  await page.route('**/api/v1/sensors', route => route.fulfill({ json: snapshot }));
  await page.route('**/api/v1/incidents', route => route.fulfill({ status: 503, json: { error: 'unavailable' } }));
  await page.goto('/');
  const overview = page.getByRole('region', { name: 'Local operational overview' });
  await expect(overview).toContainText(`${snapshot.sensors.length}`);
  await expect(overview).toContainText('Unknown');
  await expect(overview).toContainText('incident read surface is unavailable');
  await expect(overview.getByText('Complete', { exact: true })).toHaveCount(0);
});
