import { defineConfig, devices } from '@playwright/test';

const frontendBaseUrl = process.env.FRONTEND_BASE_URL ?? 'http://127.0.0.1:3000';
const reuseServer = !process.env.CI;
const shouldStartWebServer = !process.env.FRONTEND_BASE_URL && !process.env.CI;
const frontendWaitUrl = `${frontendBaseUrl.replace(/\/$/, '')}/en/`;

const config = {
  testDir: './e2e',
  timeout: 30 * 1000,
  retries: process.env.CI ? 1 : 0,
  use: {
    baseURL: frontendBaseUrl,
    headless: true,
    viewport: { width: 1280, height: 720 },
    actionTimeout: 10 * 1000,
    trace: 'on-first-retry',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
  expect: {
    toHaveScreenshot: { maxDiffPixelRatio: 0.02 },
  },
} as const;

if (shouldStartWebServer) {
  (config as Parameters<typeof defineConfig>[0]).webServer = {
    command: 'npm run dev',
    url: frontendWaitUrl,
    reuseExistingServer: reuseServer,
    timeout: 180_000,
  };
}

export default defineConfig(config);
