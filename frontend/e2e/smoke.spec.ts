const frontendBaseUrl = process.env.FRONTEND_BASE_URL ?? 'http://127.0.0.1:3000';
const backendBaseUrl = process.env.BACKEND_BASE_URL ?? 'http://127.0.0.1:8000';
const isPlaywright = process.env.PLAYWRIGHT_E2E === '1';
const hasBackend = Boolean(process.env.CI || process.env.BACKEND_BASE_URL);

if (isPlaywright) {
  const { test, expect } = require('@playwright/test');
  const {
    parseCspDirectives,
    directiveIncludes,
    getDirectiveValues,
  } = require('../tests/utils/csp');

  test('smoke: frontend home and backend health', async ({ page, request }) => {
    const normalizedFrontendUrl = frontendBaseUrl.replace(/\/$/, '');
    const localizedPath = '/en/';
    const response = await page.goto(`${normalizedFrontendUrl}${localizedPath}`, { waitUntil: 'domcontentloaded' });
    expect(response).toBeTruthy();
    expect(response?.status()).toBe(200);
    await page.waitForSelector('body');

    const headerResponse = await request.get(`${normalizedFrontendUrl}${localizedPath}`);
    const headerValues = headerResponse.headers();
    expect(headerValues["x-content-type-options"]).toBe("nosniff");
    expect(headerValues["referrer-policy"]).toBe("strict-origin-when-cross-origin");
    expect(headerValues["x-frame-options"]).toBe("SAMEORIGIN");
    expect(headerValues["permissions-policy"]).toBe("geolocation=(), microphone=(), camera=()");
    const cspHeader = headerValues['content-security-policy-report-only'];
    if (cspHeader) {
      const directives = parseCspDirectives(cspHeader);
      expect(directiveIncludes(directives, 'report-uri', '/api/v1/csp-report')).toBe(true);
      const reportToValues = getDirectiveValues(directives, 'report-to');
      if (reportToValues) {
        expect(reportToValues.length).toBeGreaterThan(0);
      }
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
    const reportingEndpoints = headerValues['reporting-endpoints'];
    if (reportingEndpoints) {
      expect(reportingEndpoints).toContain('/api/v1/csp-report');
    }
    const reportToHeader = headerValues['report-to'];
    if (reportToHeader) {
      expect(reportToHeader).toContain('/api/v1/csp-report');
    }

    if (hasBackend) {
      const reportResponse = await request.post(`${backendBaseUrl}/__csp_report`, {
        data: { timestamp: Date.now() },
        headers: { "content-type": "application/csp-report" },
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
