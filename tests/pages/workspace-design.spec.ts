import { test, expect } from '@playwright/test';

test('page search works with keyboard, filtering, escape and focus return', async ({ page }) => {
  await page.goto('./');
  const opener = page.getByRole('button', { name: 'Search workspace', exact: true });
  await opener.click();
  const dialog = page.getByRole('dialog', { name: 'Go to a workspace page' });
  const input = dialog.getByRole('searchbox', { name: 'Find a workspace page' });
  await expect(input).toBeFocused();
  await input.fill('not-a-page');
  await expect(dialog).toContainText('No pages match');
  await input.fill('incident');
  await input.press('Tab');
  await expect(dialog.getByRole('link', { name: /Incidents/ })).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(dialog).not.toBeVisible();
  await expect(page).toHaveURL(/#incidents$/);
  await page.keyboard.press('Control+k');
  await expect(dialog).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(dialog).not.toBeVisible();
});

test('theme persists across reload without persisting operational data', async ({ page }) => {
  await page.goto('./');
  const previous = await page.locator('html').getAttribute('data-theme');
  await page.getByRole('button', { name: 'Toggle color theme' }).click();
  const selected = previous === 'dark' ? 'light' : 'dark';
  await expect(page.locator('html')).toHaveAttribute('data-theme', selected);
  await page.reload();
  await expect(page.locator('html')).toHaveAttribute('data-theme', selected);
  expect(await page.evaluate(() => localStorage.getItem('miragemesh-theme'))).toBe(selected);
});

test('synthetic tour filters and replays without any operational read or write', async ({ page }) => {
  const operational: string[] = [];
  page.on('request', request => { if (request.url().includes('/api/') || request.method() !== 'GET') operational.push(request.url()); });
  await page.goto('./#sensors');
  const tour = page.getByRole('region', { name: 'Read-only synthetic product tour' });
  await expect(tour).toContainText('not connected to an engine');
  await page.getByRole('searchbox', { name: 'Search sample sensors' }).fill('demo-lab');
  await expect(tour.getByRole('row')).toHaveCount(2);
  await expect(tour).toContainText('demo-lab-03');
  await page.getByRole('searchbox', { name: 'Search sample sensors' }).fill('not-a-sensor');
  await expect(tour).toContainText('No sample sensors match');
  await page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: 'Incidents', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Previous sample event' })).toBeDisabled();
  await page.getByRole('button', { name: 'Next sample event' }).click();
  await expect(tour).toContainText('/login');
  await page.getByRole('button', { name: 'Next sample event' }).click();
  await expect(tour).toContainText('/.git/config');
  await expect(page.getByRole('button', { name: 'Next sample event' })).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Save triage' })).toHaveCount(0);
  expect(operational).toEqual([]);
});

test('all routes fit at 360px in both themes and all local icon assets load', async ({ page }) => {
  const missing: string[] = [];
  page.on('response', response => { if (response.url().includes('/assets/icons/') && response.status() !== 200) missing.push(response.url()); });
  await page.setViewportSize({ width: 360, height: 800 });
  await page.goto('./');
  for (const theme of ['dark', 'light']) {
    if (await page.locator('html').getAttribute('data-theme') !== theme) await page.getByRole('button', { name: 'Toggle color theme' }).click();
    for (const route of ['Workspace', 'Sensors', 'Incidents', 'Certificates', 'Updates', 'Roadmap']) {
      await page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: route, exact: true }).click();
      await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), route + ' ' + theme).toBe(true);
    }
  }
  expect(missing).toEqual([]);
});

test('unavailable preference storage does not prevent the public workspace', async ({ page }) => {
  await page.addInitScript(() => { Storage.prototype.getItem = () => { throw new Error('Blocked storage'); }; Storage.prototype.setItem = () => { throw new Error('Blocked storage'); }; });
  await page.goto('./');
  await expect(page.getByRole('link', { name: 'Download the Linux release', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Toggle color theme' }).click();
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
});
