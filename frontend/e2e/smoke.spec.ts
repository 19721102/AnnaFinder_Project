const frontendBaseUrl = process.env.FRONTEND_BASE_URL ?? 'http://127.0.0.1:3000';
const backendBaseUrl = process.env.BACKEND_BASE_URL ?? 'http://127.0.0.1:8000';
const isPlaywright = process.env.PLAYWRIGHT_E2E === '1';
const hasBackend = Boolean(process.env.CI || process.env.BACKEND_BASE_URL);

if (isPlaywright) {
  const { test, expect } = require('@playwright/test');

  test('smoke: frontend home and backend health', async ({ page, request }) => {
    const normalizedFrontendUrl = frontendBaseUrl.replace(/\/$/, '');
    const localizedPath = '/en/';
    const response = await page.goto(`${normalizedFrontendUrl}${localizedPath}`, { waitUntil: 'domcontentloaded' });
    expect(response).toBeTruthy();
    expect(response?.status()).toBe(200);
    await page.waitForSelector('body');

    const headerResponse = await request.get(`${normalizedFrontendUrl}${localizedPath}`);
    const cspHeaderArray = headerResponse.headersArray();
    const cspHeaderEntry = cspHeaderArray.find(
      (header) => header.name.toLowerCase() === 'content-security-policy-report-only',
    );
    const cspHeader = cspHeaderEntry?.value;
    if (cspHeader) {
      expect(cspHeader).toContain('report-to csp-endpoint');
      expect(cspHeader).toContain('report-uri /__csp_report');
    } else {
      await test.info().attach('csp-header-debug', {
        body: JSON.stringify(
          {
            url: headerResponse.url(),
            status: headerResponse.status(),
            headers: headerResponse.headersArray(),
          },
          null,
          2,
        ),
        contentType: 'application/json',
      });
      throw new Error(
        'Expected Content-Security-Policy-Report-Only header to be set on the frontend root response.',
      );
    }

    if (hasBackend) {
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
    } else {
      console.info('Skipping backend health/openapi checks; BACKEND_BASE_URL not provided locally.');
    }
  });
} else {
  describe('playwright e2e placeholder', () => {
    it('skipped under vitest', () => {});
  });
}

export {};
