import { test, expect } from '@playwright/test';
import { readFileSync } from 'node:fs';

const fixture = JSON.parse(readFileSync(new URL('../../../tests/fixtures/miragemesh/C21/expected-output.json', import.meta.url), 'utf8'));
const snapshot = { schema_version: fixture.schema_version, offline_after_seconds: fixture.offline_after_seconds, sensors: fixture.sensors };

test('sensor page displays offline, stale config and durable drops from the engine response', async ({ page }) => {
  await page.route('**/api/v1/sensors', route => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(snapshot) }));
  await page.goto('/');
  await page.getByRole('link', { name: 'Sensors', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Sensor health and spool pressure.' })).toBeVisible();
  const summary = page.getByRole('region', { name: 'Sensor summary' });
  await expect(summary.locator('.sensor-metrics')).toContainText('1');
  await expect(summary).toContainText('Offline');
  await expect(summary).toContainText('expired');
  await expect(summary).toContainText('missing');
  await expect(summary).toContainText('Dropped events');
  await expect(summary.getByRole('row', { name: /sensor-01/ })).toContainText('1');
  await expect(summary.getByRole('row', { name: /sensor-02/ })).toContainText('Online by recent event');
});

test('sensor page rejects an invalid versioned response and explains unavailable state', async ({ page }) => {
  await page.route('**/api/v1/sensors', route => route.fulfill({ status: 200, contentType: 'application/json', body: '{"schema_version":"2"}' }));
  await page.goto('/#sensors');
  await expect(page.getByRole('alert')).toContainText('Sensor status is unavailable');
});

test('sensor page keeps last snapshot explicitly stale during an outage and recovers', async ({ page }) => {
  await page.clock.install();
  let unavailable = false;
  await page.route('**/api/v1/sensors', route => unavailable
    ? route.fulfill({ status: 503, json: { error: 'sensor_status_unavailable' } })
    : route.fulfill({ json: snapshot }));
  await page.setViewportSize({ width: 360, height: 800 });
  await page.goto('/#sensors');
  await expect(page.getByRole('table')).toBeVisible();
  await expect(page.getByText('Last updated:', { exact: false })).toBeVisible();
  unavailable = true;
  await page.clock.fastForward(5000);
  await expect(page.getByRole('alert')).toContainText('stale');
  await expect(page.getByRole('table')).toBeVisible();
  await expect(page.getByRole('row', { name: /sensor-01/ })).toContainText('1');
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  unavailable = false;
  await page.clock.fastForward(5000);
  await expect(page.getByRole('alert')).toHaveCount(0);
  await expect(page.getByRole('table')).toBeVisible();
});
