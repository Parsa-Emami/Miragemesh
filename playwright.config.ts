import { defineConfig } from '@playwright/test';
const port = process.env.WEB_TEST_PORT ?? '4173';
if (!/^\d+$/.test(port) || Number(port) < 1 || Number(port) > 65535) throw new Error('Invalid WEB_TEST_PORT.');
export default defineConfig({
  testDir: './',
  testMatch: ['tests/browser/**/*.spec.ts', 'apps/web/tests/**/*.spec.ts'],
  timeout: 30000,
  use: {
    baseURL: `http://127.0.0.1:${port}`, browserName: 'chromium', headless: true,
    launchOptions: process.env.WEB_TEST_CHROMIUM ? { executablePath: process.env.WEB_TEST_CHROMIUM, args: ['--no-sandbox'] } : {},
  },
  webServer: { command: `npm start -- --port ${port}`, url: `http://127.0.0.1:${port}/readyz`, reuseExistingServer: false, timeout: 15000 },
  reporter: 'list',
});
