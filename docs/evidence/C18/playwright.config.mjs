import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: '/home/amirreza/Desktop/Projects/Miragemesh/tests/browser',
  timeout: 30000,
  use: {
    baseURL: 'http://127.0.0.1:4199',
    browserName: 'chromium',
    headless: true,
    launchOptions: { args: ['--no-sandbox'] },
  },
  webServer: {
    command: 'node /tmp/opencode/c18-start-local.mjs',
    url: 'http://127.0.0.1:4199/readyz',
    reuseExistingServer: false,
    timeout: 20000,
  },
  reporter: 'list',
});
