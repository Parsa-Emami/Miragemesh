import { defineConfig } from '@playwright/test';
export default defineConfig({
  testDir: './tests/pages',
  timeout: 30000,
  use: { baseURL: 'http://127.0.0.1:4187/Miragemesh/', browserName: 'chromium', headless: true },
  webServer: { command: 'node scripts/serve-pages-preview.mjs', url: 'http://127.0.0.1:4187/Miragemesh/', reuseExistingServer: false },
  reporter: 'list',
});
