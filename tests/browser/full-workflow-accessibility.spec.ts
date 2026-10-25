import { test, expect } from '@playwright/test';
import { readFile } from 'node:fs/promises';

const positiveFixture = JSON.parse(await readFile(new URL('../fixtures/miragemesh/C33/positive.json', import.meta.url), 'utf8'));
const negativeFixture = JSON.parse(await readFile(new URL('../fixtures/miragemesh/C33/negative.json', import.meta.url), 'utf8'));

test.describe('C33: Full Workflow Accessibility and Responsive Ergonomics', () => {
  test('keyboard navigation and table equivalents work seamlessly across 360px and 1440px viewports', async ({ page }) => {
    const pageErrors: string[] = [];
    const externalRequests: string[] = [];
    page.on('pageerror', error => pageErrors.push(error.message));
    page.on('request', request => {
      const url = request.url();
      if (!url.startsWith('http://127.0.0.1:') && !url.startsWith('http://localhost:')) {
        externalRequests.push(url);
      }
    });

    const n1 = positiveFixture.n_minus_1_compatibility;
    await page.route('**/api/v1/sensors', route => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(n1.sensor_snapshot_v0) }));
    await page.route('**/api/v1/certificates', route => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(n1.certificate_snapshot_v0) }));
    await page.route('**/api/v1/incidents', route => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(n1.incident_snapshot_v0) }));
    await page.route('**/api/v1/updates', route => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(n1.update_snapshot_v0) }));

    // 1. Skip link test on initial root navigation
    await page.setViewportSize({ width: 360, height: 800 });
    await page.goto('/');
    await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
    await page.keyboard.press('Tab');
    const skipLink = page.getByRole('link', { name: 'Skip to content' });
    await expect(skipLink).toBeFocused();
    await page.keyboard.press('Enter');
    await expect(page.locator('main#content')).toBeFocused();

    const viewports = [
      { width: 360, height: 800, name: 'mobile-360' },
      { width: 1440, height: 900, name: 'desktop-1440' },
    ];

    for (const vp of viewports) {
      await page.setViewportSize({ width: vp.width, height: vp.height });

      // Workspace route
      await page.goto('/#workspace');
      await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), `horizontal overflow on workspace at ${vp.width}px`).toBe(true);

      // Sensors route
      await page.goto('/#sensors');
      await expect(page.getByRole('heading', { name: 'Sensor health and spool pressure.' })).toBeVisible();
      const sensorTableWrap = page.getByRole('region', { name: 'Sensor status table' });
      await expect(sensorTableWrap).toBeVisible();
      await expect(sensorTableWrap.getByRole('row', { name: /sensor-n1-01/ })).toContainText('Online by recent event');
      await expect(sensorTableWrap.getByRole('row', { name: /sensor-n1-01/ })).toContainText('current');
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), `horizontal overflow on sensors at ${vp.width}px`).toBe(true);

      // Incidents route
      await page.goto('/#incidents');
      await expect(page.getByRole('heading', { name: 'Incident replay and triage.' })).toBeVisible();
      const incidentTableWrap = page.getByRole('region', { name: 'Incident table' });
      await expect(incidentTableWrap).toBeVisible();
      const openButton = incidentTableWrap.getByRole('button', { name: /Open replay|Open incident 1/ });
      await expect(openButton).toBeVisible();
      await openButton.click();

      // Triage form interactive elements reachable
      await expect(page.getByRole('region', { name: 'Selected incident' })).toBeVisible();
      await expect(page.getByLabel('Triage status')).toBeVisible();
      await expect(page.getByLabel('Triage reason')).toBeVisible();
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), `horizontal overflow on incidents at ${vp.width}px`).toBe(true);

      // Certificates route
      await page.goto('/#certificates');
      await expect(page.getByRole('heading', { name: 'Certificate rotation and recovery.' })).toBeVisible();
      const certRegion = page.getByRole('region', { name: 'Certificate status' });
      await expect(certRegion).toContainText('sensor-n1-01');
      await expect(certRegion).toContainText('Current certificate');
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), `horizontal overflow on certificates at ${vp.width}px`).toBe(true);

      // Updates route
      await page.goto('/#updates');
      await expect(page.getByRole('heading', { name: 'Signed sensor updates.' })).toBeVisible();
      const updateRegion = page.getByRole('region', { name: 'Update verification' });
      await expect(updateRegion).toContainText('sensor-n1-01');
      await expect(updateRegion).toContainText('Platform: linux/amd64');
      await expect(updateRegion).toContainText('Verified release 1');
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), `horizontal overflow on updates at ${vp.width}px`).toBe(true);

      // Roadmap route
      await page.goto('/#roadmap');
      await expect(page.getByRole('heading', { name: 'A clear path to release.' })).toBeVisible();
      await page.getByLabel('Search tasks').fill('C33');
      await expect(page.locator('.tasks')).toContainText('C33');
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), `horizontal overflow on roadmap at ${vp.width}px`).toBe(true);
    }

    // Verify security constraints: no external egress and no leaked private keys
    expect(externalRequests).toEqual([]);
    expect(pageErrors).toEqual([]);
    const bodyContent = await page.locator('body').textContent();
    expect(bodyContent).not.toContain('-----BEGIN PRIVATE KEY-----');
    expect(bodyContent).not.toContain('-----BEGIN CERTIFICATE REQUEST-----');
  });

  test('failure, empty, invalid, and provider-outage modes remain explicit and accessible', async ({ page }) => {
    await page.setViewportSize({ width: 360, height: 800 });

    // 1. Engine provider outage (503)
    await page.route('**/api/engine/health', route => route.fulfill({ status: 503, contentType: 'application/json', body: '{"error":"engine_unavailable"}' }));
    await page.goto('/#workspace');
    await expect(page.getByRole('region', { name: 'Availability' })).toContainText('Engine runtime unavailable');

    // 2. Empty states on all domain pages
    await page.route('**/api/v1/sensors', route => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ schema_version: '1', offline_after_seconds: 300, sensors: [] }) }));
    await page.route('**/api/v1/certificates', route => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ schema_version: '1', observed_at: '2026-10-25T12:00:00Z', issuer_fingerprint: 'a'.repeat(64), sensors: [] }) }));
    await page.route('**/api/v1/incidents', route => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ schema_version: '1', coverage: { complete: true, incomplete_segments: 0, missing_ordinals: [] }, unprojected_events: 0, rate_limit: 2, window_seconds: 60, incidents: [] }) }));
    await page.route('**/api/v1/updates', route => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ schema_version: '1', platform: 'linux/amd64', publisher_fingerprint: 'a'.repeat(64), recovery_fingerprint: 'b'.repeat(64), observed_at: '2026-10-25T12:00:00Z', sensors: [] }) }));

    await page.goto('/#sensors');
    await expect(page.getByRole('region', { name: 'Sensor summary' })).toContainText('No sensor records are available in local storage.');

    await page.goto('/#incidents');
    await expect(page.locator('main')).toContainText('No incidents in the projected segments.');

    await page.goto('/#certificates');
    await expect(page.getByRole('region', { name: 'Certificate status' })).toContainText('No sensor certificates have been registered.');

    await page.goto('/#updates');
    await expect(page.getByRole('region', { name: 'Update verification' })).toContainText('No signed update metadata has been accepted.');

    // 3. Sensor 503 provider outage
    await page.route('**/api/v1/sensors', route => route.fulfill({ status: 503, contentType: 'application/json', body: '{"error":"sensors_unavailable"}' }));
    await page.goto('/#sensors');
    await expect(page.getByRole('alert')).toContainText('Sensor status is unavailable');

    // 4. Incident 503 provider outage
    await page.route('**/api/v1/incidents', route => route.fulfill({ status: 503, contentType: 'application/json', body: '{"error":"incidents_unavailable"}' }));
    await page.goto('/#incidents');
    await expect(page.getByRole('alert')).toContainText('Incidents are unavailable');

    // 5. Corrupted response payload produces explicit non-crashing alert
    await page.route('**/api/v1/sensors', route => route.fulfill({ status: 200, contentType: 'application/json', body: '{"corrupted":true' }));
    await page.goto('/#sensors');
    await expect(page.getByRole('alert')).toContainText('Sensor status is unavailable because the engine response is invalid.');

    // Responsive check under error state at 360px
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  });
});
