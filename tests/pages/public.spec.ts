import { test, expect } from '@playwright/test';

test('public subpath works without operational API calls and keeps navigation and local preview usable', async ({ page }) => {
  const api: string[] = [];
  page.on('request', request => { if (/\/api\//.test(request.url())) api.push(request.url()); });
  const errors: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.goto('./');
  await expect(page.getByRole('link', { name: 'Download the Linux release' })).toBeVisible();
  for (const name of ['Sensors', 'Incidents', 'Certificates', 'Updates']) {
    await page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name, exact: true }).click();
    await expect(page.getByRole('heading', { name: `Use ${name.toLowerCase()} in your local workspace` })).toBeVisible();
  }
  await page.getByRole('link', { name: 'Roadmap', exact: true }).click();
  await page.getByRole('searchbox', { name: 'Search tasks' }).fill('C40');
  await expect(page.getByText('1 of 40 product tasks')).toBeVisible();
  expect(api).toEqual([]);
  expect(errors).toEqual([]);
});

test('public workspace fits a narrow screen and supports keyboard navigation', async ({ page }) => {
  await page.setViewportSize({ width: 360, height: 780 });
  await page.goto('./');
  await expect(page.getByRole('link', { name: 'Download the Linux release' })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.keyboard.press('Tab');
  await expect(page.getByRole('link', { name: 'Skip to content' })).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(page.locator('#content')).toBeFocused();
});
