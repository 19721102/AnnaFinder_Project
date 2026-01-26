const frontendBaseUrl = process.env.FRONTEND_BASE_URL ?? 'http://127.0.0.1:3000';
const backendBaseUrl = process.env.BACKEND_BASE_URL ?? 'http://127.0.0.1:8000';
const isPlaywright = process.env.PLAYWRIGHT_E2E === '1';

if (isPlaywright) {
  const { test, expect } = require('@playwright/test');

  test('smoke: frontend home and backend health', async ({ page, request }) => {
    const response = await page.goto(frontendBaseUrl, { waitUntil: 'domcontentloaded' });
    expect(response).toBeTruthy();
    expect(response?.status()).toBe(200);
    await page.waitForSelector('body');

    const cspHeader = response?.headers()['content-security-policy-report-only'];
    expect(cspHeader).toBeTruthy();
    expect(cspHeader).toContain('report-to csp-endpoint');

    const reportResponse = await request.post(`${backendBaseUrl}/__csp_report`, {
      data: { timestamp: Date.now() },
    });
    expect(reportResponse.status()).toBe(204);

    const health = await request.get(`${backendBaseUrl}/healthz`);
    expect(health.status()).toBe(200);
    const healthJson = await health.json();
    expect(healthJson.status).toBe('ok');

    const openapi = await request.get(`${backendBaseUrl}/openapi.json`);
    expect(openapi.status()).toBe(200);
    const openapiJson = await openapi.json();
    expect(openapiJson).toHaveProperty('openapi');
  });
} else {
  describe('playwright e2e placeholder', () => {
    it('skipped under vitest', () => {});
  });
}

export {};
